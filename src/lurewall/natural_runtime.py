# SPDX-License-Identifier: AGPL-3.0-only
"""nginx njs request handler. PROFILE is supplied by the local vhost build."""

JAVASCRIPT = r"""
import crypto from 'crypto';
import fs from 'fs';

function mac(label) {
    return crypto.createHmac('sha256', PROFILE.key).update(label).digest('hex');
}

function uint(s) { return parseInt(s.slice(0, 8), 16); }

function readBucket(path) {
    try {
        return JSON.parse(fs.readFileSync(path, 'utf8'));
    } catch (e) {
        if (e.code === 'ENOENT') return [];
        throw e;
    }
}

// One private file per bucket, at most eight live leases per file. A crashed
// writer can disable one bucket; readers always see the last complete file.
function lease(tag, now) {
    var base = PROFILE.leases + '/' + tag.slice(0, 3);
    var rows = readBucket(base);
    var match = rows.find(row => row.tag === tag && row.until > now);
    if (match) return match;
    try {
        fs.mkdirSync(base + '.lock', 448);
    } catch (e) {
        if (e.code === 'EEXIST') return undefined;
        throw e;
    }
    try {
        rows = readBucket(base).filter(row => row.until > now);
        match = rows.find(row => row.tag === tag);
        if (match) return match;
        if (rows.length >= 8) return null;
        var jitter = uint(mac('ttl:' + tag + ':' + now)) % (4 * 86400 + 1);
        match = {tag: tag, start: now, until: now + 3 * 86400 + jitter};
        rows.push(match);
        fs.writeFileSync(base + '.next', JSON.stringify(rows), {mode: 384});
        fs.renameSync(base + '.next', base);
        return match;
    } finally {
        fs.rmdirSync(base + '.lock');
    }
}

function sourceTag(r) {
    var raw = r.rawVariables.binary_remote_addr;
    if (!raw || (raw.length !== 4 && raw.length !== 16)) return '';
    var hex = raw.toString('hex');
    if (raw.length === 16 && hex.slice(0, 24) === '00000000000000000000ffff') {
        hex = hex.slice(24);
    } else if (raw.length === 16) {
        hex = hex.slice(0, 16);
    }
    return mac('source:' + hex);
}

function generator(label) {
    var block = '';
    var count = 0;
    return function (n) {
        if (block.length < 8) block = mac(label + ':' + (count++));
        var value = uint(block) % n;
        block = block.slice(8);
        return value;
    };
}

function reference(carrier, row) {
    var seed = row.tag + ':' + row.start;
    var rng = generator('partition:' + seed);
    var words = PROFILE.words.slice();
    for (var i = words.length - 1; i > 0; i--) {
        var j = rng(i + 1), temp = words[i];
        words[i] = words[j];
        words[j] = temp;
    }
    // Disjoint vocabularies for this source's active placements.
    var pool = words.filter((word, index) => index % PROFILE.count === carrier.slot);
    var pick = generator('reference:' + carrier.id + ':' + seed);
    for (var tryNo = 0; tryNo < 24; tryNo++) {
        var available = pool.slice();
        var days = 14 + pick(3 * 365);
        var date = new Date((row.start - days * 86400) * 1000).toISOString().slice(0, 10);
        var path = carrier.style.replace(/W|V|D|Y|M|T/g, function (token) {
            if (token === 'V') return String(1 + pick(12));
            if (token === 'D') return date;
            if (token === 'Y') return date.slice(0, 4);
            if (token === 'M') return date.slice(5, 7);
            if (token === 'T') return date.slice(8, 10);
            return available.splice(pick(available.length), 1)[0];
        });
        var key = path.replace(/\/$/, '');
        if (PROFILE.routes[key]) continue;
        try {
            fs.accessSync(PROFILE.root + key);
        } catch (e) {
            if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return path;
        }
    }
    return '';
}

async function serve(r) {
    var c = PROFILE.carriers[r.uri];
    if (!c) { r.return(404); return; }
    if (r.method !== 'GET' && r.method !== 'HEAD') { r.return(405); return; }
    var now = Math.floor(Date.now() / 1000);
    var path = '', row, body, mtime;
    try {
        var info = fs.statSync(c.file);
        if (!info.isFile() || info.size > 524288) {
            r.internalRedirect(c.fallback);
            return;
        }
        body = fs.readFileSync(c.file);
        mtime = Math.min(Math.floor(info.mtimeMs / 1000), now);
        var unchanged = crypto.createHash('sha256').update(body).digest('hex') === c.hash;
        var tag = sourceTag(r);
        if (tag && unchanged && (!c.expires || c.expires > now)) {
            try {
                for (var attempt = 0; attempt < 4; attempt++) {
                    row = lease(tag, now);
                    if (row !== undefined) break;
                    await new Promise(resolve => setTimeout(resolve, 5));
                }
                if (row) path = reference(c, row);
            } catch (e) {
                r.warn('Lurewall issuance storage unavailable; serving original resource');
            }
        }
        if (!path) { r.internalRedirect(c.fallback); return; }
        body = Buffer.from(c.before + path + c.after);
        r.variables.lw_placement = c.id;
        r.variables.lw_path = path;
        r.variables.lw_until = String(row.until);
        // Conditional requests and HEAD must never be interpreted as issuing a body.
        r.headersOut['Content-Type'] = c.type;
        r.headersOut['Cache-Control'] = 'private, no-cache';
        r.headersOut['ETag'] = '"' + crypto.createHash('sha256').update(body).digest('hex') + '"';
        r.headersOut['Last-Modified'] = new Date(mtime * 1000).toUTCString();
        r.return(200, body);
    } catch (e) {
        r.internalRedirect(c.fallback);
    }
}

export default {serve};
"""
