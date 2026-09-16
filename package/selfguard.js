/* METADATA
{
  "name": "selfguard",
  "display_name": {
    "zh": "破甲自检·加固助手",
    "en": "ArmorBreak Self-Audit & Harden"
  },
  "description": {
    "zh": "以“攻击者/逆向视角”对【自有或已授权】工程做破甲演练式安全自检：扫描源码与发布产物中的硬编码凭据、弱加密/伪加密、危险动态执行、混淆残留、sourcemap 泄漏与信息暴露等弱点，输出风险分级、行号定位与加固建议，用于避免被破译、排查漏洞和编写更安全的代码。本插件仅用于学习和参考，只允许检测本人拥有或已获授权分析的工程；严禁用于绕过他人版权、授权、DRM 或访问控制。",
    "en": "Armor-break drill self-audit for your OWN or authorized projects: scans source & artifacts for hardcoded credentials, weak/pseudo encryption, dangerous dynamic execution, obfuscation remnants, sourcemap leaks and information exposure; returns severity-ranked findings with line numbers and hardening advice to avoid reverse engineering, find vulnerabilities, and write safer code. For learning & reference only; scan only projects you own or are authorized to analyze. Never for bypassing others' copyright, licensing, DRM or access controls."
  },
  "category": "Security",
  "enabledByDefault": true,
  "tools": [
    {
      "name": "selfguard",
      "description": {
        "zh": "破甲自检·加固助手（只读、不联网、不修改文件）。action=scan_source：递归扫描指定源码/工程目录，输出风险清单（文件/行号/类别/级别/建议）；action=probe_artifact：对单个发布产物(.js/.json/.txt 或 .toolpkg 容器)做“若被拿到手能还原出什么”的结构化探测与可逆性评估；action=report：生成汇总加固报告（含检查清单 Markdown）。path 为目标文件或目录，默认 android 环境。仅限学习/参考与自有或已授权工程。",
        "en": "ArmorBreak self-audit & hardening helper (read-only, offline). action=scan_source: recursively scan source/project directory and output risk list (file/line/category/severity/advice); action=probe_artifact: structurally probe a single artifact to estimate what a reverser could extract and reversibility score; action=report: aggregated hardening report with checklist (Markdown). path=target file or directory; android env by default. Learning/reference only; own or authorized projects only."
      },
      "parameters": [
        { "name": "action", "description": { "zh": "动作：scan_source / probe_artifact / report，默认 scan_source", "en": "Action: scan_source / probe_artifact / report, default scan_source" }, "type": "string", "required": false },
        { "name": "path", "description": { "zh": "目标文件或目录（本人的/已授权工程）", "en": "Target file or directory (own or authorized project)" }, "type": "string", "required": true },
        { "name": "environment", "description": { "zh": "可选：android/linux，默认 android", "en": "Optional: android/linux, default android" }, "type": "string", "required": false },
        { "name": "max_depth", "description": { "zh": "目录扫描最大深度，默认 8", "en": "Max directory scan depth, default 8" }, "type": "number", "required": false },
        { "name": "max_files", "description": { "zh": "最多扫描文件数，默认 300", "en": "Max files to scan, default 300" }, "type": "number", "required": false },
        { "name": "max_findings", "description": { "zh": "返回的最大风险条数，默认 150", "en": "Max findings returned, default 150" }, "type": "number", "required": false }
      ]
    }
  ]
}
*/
const DISCLAIMER_ZH = "【声明】本插件仅用于学习和参考，仅允许检测本人拥有或已获授权分析的工程/文件；请勿用于绕过他人版权、授权、DRM、支付或访问控制等任何越界用途。";
const DISCLAIMER_EN = "[Notice] This plugin is for learning & reference only. Scan only projects/files you own or are authorized to analyze. Never use it to bypass others' copyright, licensing, DRM, payment or access controls.";
const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_FILES = 300;
const DEFAULT_MAX_FINDINGS = 150;
const CONTENT_LIMIT = 400000;
const SKIP_DIR_NAMES = ["node_modules", ".git", ".svn", ".hg", ".idea", ".vscode", ".gradle", ".cache", ".next", ".nuxt", "coverage", "build", "backup", ".terraform"];
const TEXT_FILE_RE = /\.(ts|tsx|js|mjs|cjs|jsx|json|json5|hjson|html?|vue|css|scss|less|xml|ya?ml|md|markdown|txt|log|sh|bash|zsh|py|pyw|java|kt|kts|gradle|properties|env|ini|toml|cfg|conf|sql|php|rb|go|rs|c|h|cpp|hpp|cc|cs|swift|plist|svg|bat|ps1|map)$/i;
const BINARY_FILE_RE = /\.(png|jpe?g|gif|webp|bmp|ico|mp3|mp4|mkv|avi|mov|webm|zip|rar|7z|gz|bz2|xz|apk|aab|jar|dex|so|wasm|toolpkg|class|pdf|docx?|xlsx?|ttf|otf|woff2?|bin|exe|dll|obj|o|a|pyc)$/i;
const SPECIAL_TEXT_NAMES = /^(dockerfile|makefile|gnumakefile|jenkinsfile|procfile|license|notice|readme|changelog|\.env.*)$/i;
// 静态规则（只读启发式；用于“自检”而非“攻击他人”，无任何写/联网行为）
const RISK_RULES = [
    {
        id: "hardcoded_credential",
        category: "硬编码凭据",
        severity: "high",
        label: "疑似硬编码密钥/口令赋值",
        regex: /\b(api[_-]?key|apikey|secret|passwd|password|pwd|access[_-]?token|auth[_-]?token|client[_-]?secret|authorization|bearer[_-]?token)\b\s*[:=]\s*["'][^"'\r\n]{6,}["']/gi,
        advice: "密钥/口令应存放于宿主环境变量或独立 env 文件，并做好权限控制；严禁写入源码或发布产物。"
    },
    {
        id: "known_secret_prefix",
        category: "凭据/私钥泄漏",
        severity: "high",
        label: "疑似真实密钥/私钥/令牌格式",
        regex: /(sk-[A-Za-z0-9_\-]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_\-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z\-]{10,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/g,
        advice: "该片段符合常见真实凭据/私钥格式，若属真应立即撤销轮换并从历史提交中清除；建议接入密钥扫描流水线。"
    },
    {
        id: "url_with_secret",
        category: "URL 内嵌密钥",
        severity: "high",
        label: "URL 查询串携带密钥类参数",
        regex: /https?:\/\/[^\s"'<>]*(?:access_token|api[_-]?key|token|secret|password|signature|apikey)=[^\s"'<>]+/gi,
        advice: "URL 中的密钥会出现在日志/历史/中转代理中；应改为服务端代理或在请求头携带，并使用短期凭证。"
    },
    {
        id: "weak_crypto",
        category: "弱加密算法",
        severity: "high",
        label: "使用了可快速破解的加密/摘要算法",
        regex: /CryptoJS\s*\.\s*(?:DES|TripleDES|RC4|Rabbit|MD5|SHA1|HmacMD5|HmacSHA1)(?:\.[A-Za-z]+)?\s*\(/gi,
        advice: "DES/RC4/MD5/SHA1 等已被证明不安全；改用 AES-GCM 等经过认证的加密，口令散列使用 bcrypt/argon2。"
    },
    {
        id: "ecb_mode",
        category: "弱加密模式",
        severity: "high",
        label: "ECB 模式（分块无随机性，模式可辨）",
        regex: /CryptoJS\.mode\.ECB/gi,
        advice: "ECB 不隐藏数据模式，易被还原；请改用 CBC/CTR/GCM 并搭配随机 IV 与认证。"
    },
    {
        id: "dangerous_exec",
        category: "危险动态执行",
        severity: "high",
        label: "eval/动态函数/命令执行类调用",
        regex: /\beval\s*\(|new\s+Function\s*\(|\bexec(?:Sync)?\s*\(|child_process|\bspawn\s*\(|ProcessBuilder|Runtime\.getRuntime\(\).*exec/gi,
        advice: "若拼接不可信输入会形成代码/命令注入；尽量使用白名单与参数化调用，禁止直接执行外部字符串。"
    },
    {
        id: "dynamic_require",
        category: "危险动态执行",
        severity: "medium",
        label: "动态 require/import 路径",
        regex: /\brequire\s*\(\s*[^"'`\r\n(][^)\r\n]*\)/g,
        advice: "动态模块路径可能被用于路径注入或增加还原难度假象；静态 import 更可审计。"
    },
    {
        id: "obfuscation_marker",
        category: "混淆残留",
        severity: "medium",
        label: "检测到混淆器特征（_0x 变量等）",
        regex: /_0x[0-9a-f]{4,}/g,
        advice: "字符串混淆只能提高门槛，无法防逆向；请同时把密钥外置、接口鉴权，并假设逻辑迟早可被还原。"
    },
    {
        id: "obfuscation_lib",
        category: "混淆残留",
        severity: "low",
        label: "混淆器关键字/配置残留",
        regex: /javascript-obfuscator|obfuscator\.io|js-obfuscator|\bdeadcode\b/gi,
        advice: "发布前请确认混淆配置未泄露 seed/password 等参数；混淆不等于加密。"
    },
    {
        id: "sourcemap_leak",
        category: "Sourcemap 泄漏",
        severity: "high",
        label: "产物携带 sourceMappingURL/sourceURL",
        regex: /\/\/[#@]\s*(?:sourceMappingURL|sourceURL)=/g,
        advice: "sourcemap 等于把源码/映射直接交付给逆向者；线上发布必须移除或仅在私有调试环境提供。"
    },
    {
        id: "debugger_statement",
        category: "调试残留",
        severity: "low",
        label: "debugger 语句残留",
        regex: /\bdebugger\s*;/g,
        advice: "清理调试断点语句，避免异常中断与暴露内部状态。"
    },
    {
        id: "pseudo_encryption",
        category: "伪加密",
        severity: "low",
        label: "仅压缩/编码却被当作加密的用法",
        regex: /\bpako\.(?:deflate|gzip|deflateRaw)\b|\bbtoa\s*\(\s*JSON\.stringify/gi,
        advice: "pako 压缩与 base64 编码不是加密，任何人都能还原；敏感数据必须使用真正的加密方案。"
    },
    {
        id: "internal_path_exposure",
        category: "信息暴露",
        severity: "low",
        label: "暴露内部绝对路径/数据目录",
        regex: /\/sdcard\/Download\/Operit|\/storage\/emulated\/0|Android\/data\/com\.ai\.assistance\.operit/g,
        advice: "发布产物中尽量移除本机绝对路径，避免为定位内部结构提供线索。"
    }
];
const HARDEN_CHECKLIST = [
    "1. 凭据管理：所有 key/token/password 移到宿主环境变量或密钥库，禁止进源码/产物；历史提交一并清除并轮换。",
    "2. 密码学：使用经过认证的现代算法（AES-GCM/ChaCha20，口令用 argon2/bcrypt）；不用 DES/ECB/MD5/SHA1 自造协议。",
    "3. 输入安全：杜绝 eval/动态函数/拼接命令执行；对外部输入做白名单与参数化。",
    "4. 交付物：发布产物移除 sourcemap、注释中的内部路径、作者邮箱等指纹；混淆可作为门槛但不要依赖它。",
    "5. 完整性：对发布文件计算并校验签名/哈希，防止被篡改后再分发。",
    "6. 最小暴露：只读/写需要的最小路径，运行权限最小化，敏感操作走鉴权接口而非本地硬编码密钥。",
    "7. 依赖治理：定期扫描第三方依赖漏洞（如 OSV/供应链扫描），锁定版本并审计 license。",
    "8. 持续自检：把本工具接入 CI/发布前检查，形成“先破甲、再加固、再发布”的闭环。"
];
function normalizeResult(r) {
    if (!r) {
        return r;
    }
    if (r.data && r.data && typeof r.data === "object" && !r.entries && !r.content && !r.exists && r.data.entries !== undefined) {
        return r.data;
    }
    return r;
}
async function fsList(path, env) {
    let r;
    try {
        r = normalizeResult(await Tools.Files.list(path, env));
    }
    catch (e) {
        return [];
    }
    const entries = (r && r.entries) || [];
    return Array.isArray(entries) ? entries : [];
}
async function fsExists(path, env) {
    try {
        const r = normalizeResult(await Tools.Files.exists(path, env));
        return !!(r && r.exists);
    }
    catch (e) {
        return false;
    }
}
async function fsInfo(path, env) {
    try {
        return normalizeResult(await Tools.Files.info(path, env));
    }
    catch (e) {
        return null;
    }
}
function isTextFile(name) {
    const n = name || "";
    if (BINARY_FILE_RE.test(n)) {
        return false;
    }
    if (TEXT_FILE_RE.test(n)) {
        return true;
    }
    return SPECIAL_TEXT_NAMES.test(n);
}
function isSkipDir(name) {
    return SKIP_DIR_NAMES.indexOf(name) >= 0;
}
function buildSegments(content) {
    if (!content) {
        return [];
    }
    if (content.length <= CONTENT_LIMIT) {
        return [{ text: content, base: 0 }];
    }
    const head = content.slice(0, CONTENT_LIMIT);
    const tail = content.slice(content.length - CONTENT_LIMIT);
    const headNewlines = head.split("\n").length - 1;
    return [
        { text: head, base: 0 },
        { text: "\n<<<<< [内容过长，仅展示头/尾抽样] >>>>>\n" + tail, base: headNewlines + 1 }
    ];
}
async function readSegments(path, env) {
    try {
        const r = normalizeResult(await Tools.Files.read({ path: path, environment: env }));
        const content = (r && typeof r.content === "string") ? r.content : (r && typeof r === "string" ? r : "");
        return { ok: true, segments: buildSegments(content) };
    }
    catch (e) {
        return { ok: false, segments: [], error: String((e && e.message) || e) };
    }
}
function snippetAround(content, index, radius) {
    const start = Math.max(0, index - radius);
    const end = Math.min(content.length, index + radius);
    const s = content.slice(start, end).replace(/\r?\n/g, " ").replace(/\s+/g, " ").trim();
    return s.length > 220 ? s.slice(0, 220) + "…" : s;
}
function scanText(file, content) {
    const out = [];
    if (!content || content.length === 0) {
        return out;
    }
    const segments = buildSegments(content);
    for (let sIdx = 0; sIdx < segments.length; sIdx += 1) {
        const seg = segments[sIdx];
        for (let ri = 0; ri < RISK_RULES.length; ri += 1) {
            const rule = RISK_RULES[ri];
            const re = new RegExp(rule.regex.source, rule.regex.flags);
            let m;
            while ((m = re.exec(seg.text)) !== null) {
                if (m.index === re.lastIndex) {
                    re.lastIndex += 1;
                }
                const lineInSeg = seg.text.slice(0, m.index).split("\n").length;
                out.push({
                    file: file,
                    line: seg.base + lineInSeg,
                    rule: rule.id,
                    category: rule.category,
                    label: rule.label,
                    severity: rule.severity,
                    snippet: snippetAround(seg.text, m.index, 70),
                    advice: rule.advice
                });
                if (out.length >= 400) {
                    return out;
                }
            }
        }
    }
    return out;
}
async function walkFiles(root, maxDepth, maxFiles, env) {
    const files = [];
    const errors = [];
    async function rec(dir, depth) {
        if (files.length >= maxFiles || depth > maxDepth) {
            return;
        }
        const entries = await fsList(dir, env);
        for (let i = 0; i < entries.length; i += 1) {
            if (files.length >= maxFiles) {
                return;
            }
            const en = entries[i];
            if (typeof en === "string") {
                files.push(dir.replace(/\/+$/, "") + "/" + en);
                continue;
            }
            const name = (en && (en.name || en.fileName)) || "";
            if (!name) {
                continue;
            }
            const full = dir.replace(/\/+$/, "") + "/" + name;
            if (en.isDirectory) {
                if (!isSkipDir(name)) {
                    await rec(full, depth + 1);
                }
            }
            else if (isTextFile(name)) {
                files.push(full);
            }
        }
    }
    const info = await fsInfo(root, env);
    const isDir = info ? info.fileType === "directory" || (info.exists && !info.size) : true;
    if (isDir) {
        await rec(root, 0);
    }
    else if (isTextFile(root.split("/").pop() || "")) {
        files.push(root);
    }
    return { files: files, errors: errors };
}
async function scanSource(path, env, maxDepth, maxFiles, maxFindings) {
    const started = Date.now();
    const { files, errors } = await walkFiles(path, maxDepth, maxFiles, env);
    const findings = [];
    const fileErrors = [];
    let totalBytes = 0;
    const perFileStats = [];
    const fileLimit = Math.min(maxFiles, 300);
    const used = files.length <= fileLimit ? files : files.slice(0, fileLimit);
    for (let i = 0; i < used.length; i += 1) {
        const f = used[i];
        const segRes = await readSegments(f, env);
        if (!segRes.ok) {
            fileErrors.push(f + " :: " + (segRes.error || "读取失败"));
            continue;
        }
        let contentLen = 0;
        for (let j = 0; j < segRes.segments.length; j += 1) {
            contentLen += segRes.segments[j].text.length;
        }
        totalBytes += contentLen;
        const whole = segRes.segments.map((s) => s.text).join("");
        const found = scanText(f, whole);
        if (found.length > 0) {
            perFileStats.push({ file: f, hits: found.length, bytes: contentLen });
            for (let k = 0; k < found.length && findings.length < maxFindings; k += 1) {
                findings.push(found[k]);
            }
        }
    }
    const summary = { scanned_files: used.length, total_bytes: totalBytes, truncated_hint: "超长文件仅头尾抽样", total: findings.length };
    const bySeverity = { high: 0, medium: 0, low: 0 };
    const byCategory = {};
    for (let i = 0; i < findings.length; i += 1) {
        const f = findings[i];
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        byCategory[f.category] = byCategory[f.category] || { high: 0, medium: 0, low: 0, total: 0 };
        byCategory[f.category][f.severity] = (byCategory[f.category][f.severity] || 0) + 1;
        byCategory[f.category].total += 1;
    }
    summary.by_severity = bySeverity;
    summary.by_category = byCategory;
    summary.duration_ms = Date.now() - started;
    return {
        action: "scan_source",
        target: path,
        summary: summary,
        findings: findings,
        top_files: perFileStats.slice(0, 20),
        file_errors: fileErrors.slice(0, 20),
        errors: errors.slice(0, 20),
        disclaimer: DISCLAIMER_ZH
    };
}
function severityWeight(sev) {
    if (sev === "high") {
        return 4;
    }
    if (sev === "medium") {
        return 2;
    }
    return 1;
}
const ZIP_CONTAINER_RE = /\.(toolpkg|zip|apk|jar|aab|ipa|epub|whl)$/i;
const SOURCE_TELL_RE = /\.(ts|tsx|map|rs|kt|java|py|cs|go|mjs|cjs)$/i;
const ENTRY_READ_LIMIT = 6;
function b64ToBytes(b64) {
    const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const clean = String(b64 || "").replace(/[^A-Za-z0-9+/=]/g, "");
    const out = [];
    let buffer = 0;
    let bits = 0;
    for (let i = 0; i < clean.length; i += 1) {
        const ch = clean.charAt(i);
        if (ch === "=") {
            break;
        }
        const v = CHARS.indexOf(ch);
        if (v < 0) {
            continue;
        }
        buffer = ((buffer << 6) | v) & 0xffffff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push((buffer >> bits) & 0xff);
        }
    }
    return out;
}
function bytesToUtf8(arr) {
    let s = "";
    let i = 0;
    const n = arr.length;
    while (i < n) {
        const b = arr[i];
        i += 1;
        if (b < 0x80) {
            s += String.fromCharCode(b);
        }
        else if (b >= 0xc0 && b < 0xe0 && i < n) {
            s += String.fromCharCode(((b & 0x1f) << 6) | (arr[i] & 0x3f));
            i += 1;
        }
        else if (b >= 0xe0 && b < 0xf0 && i + 1 < n) {
            s += String.fromCharCode(((b & 0x0f) << 12) | ((arr[i] & 0x3f) << 6) | (arr[i + 1] & 0x3f));
            i += 2;
        }
        else if (b >= 0xf0 && i + 2 < n) {
            const cp = ((b & 0x07) << 18) | ((arr[i] & 0x3f) << 12) | ((arr[i + 1] & 0x3f) << 6) | (arr[i + 2] & 0x3f);
            const cc = cp - 0x10000;
            s += String.fromCharCode(0xd800 + (cc >> 10), 0xdc00 + (cc & 0x3ff));
            i += 3;
        }
    }
    return s;
}
function parseZipEntries(bytes) {
    const n = bytes.length;
    if (n < 22) {
        return null;
    }
    const rd16 = function (o) { return bytes[o] | (bytes[o + 1] << 8); };
    const rd32 = function (o) { return (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0; };
    let eocd = -1;
    const back = Math.min(n, 66000);
    for (let i = n - 22; i >= n - back && i >= 0; i -= 1) {
        if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) {
        return null;
    }
    const total = rd16(eocd + 10);
    let off = rd32(eocd + 16);
    const entries = [];
    for (let k = 0; k < total; k += 1) {
        if (off + 46 > n) {
            break;
        }
        if (!(bytes[off] === 0x50 && bytes[off + 1] === 0x4b && bytes[off + 2] === 0x01 && bytes[off + 3] === 0x02)) {
            break;
        }
        const method = rd16(off + 10);
        const csize = rd32(off + 20);
        const usize = rd32(off + 24);
        const nameLen = rd16(off + 28);
        const extraLen = rd16(off + 30);
        const commentLen = rd16(off + 32);
        const localOff = rd32(off + 42);
        const name = bytesToUtf8(bytes.slice(off + 46, off + 46 + nameLen));
        entries.push({ name: name, method: method, csize: csize, usize: usize, localOff: localOff });
        off = off + 46 + nameLen + extraLen + commentLen;
    }
    return entries;
}
async function probeBinaryContainer(path, env, info, started) {
    if (typeof Tools === "undefined" || !Tools.Files || typeof Tools.Files.readBinary !== "function") {
        return null;
    }
    let payload = null;
    try {
        payload = normalizeResult(await Tools.Files.readBinary(path, env));
    }
    catch (e) {
        return null;
    }
    const node = (payload && payload.data && typeof payload.data === "object") ? payload.data : payload;
    const b64 = (node && (node.contentBase64 || node.base64)) || (payload && payload.contentBase64) || null;
    if (!b64 || typeof b64 !== "string") {
        return null;
    }
    const bytes = b64ToBytes(b64);
    const sizeBytes = (info && info.size) || (node && node.size) || bytes.length;
    let entries = null;
    try {
        entries = parseZipEntries(bytes);
    }
    catch (e) {
        entries = null;
    }
    if (!entries || !entries.length) {
        return {
            action: "probe_artifact",
            target: path,
            ok: true,
            container: "二进制/非文本文件",
            size_bytes: sizeBytes,
            message: "该文件为二进制产物，沙盒宿主无法做文本层探测；请先用解压/反编译手段解开后，再对内部 js/json 执行 probe_artifact（仅限自有/已授权文件）。",
            duration_ms: Date.now() - started,
            disclaimer: DISCLAIMER_ZH
        };
    }
    const names = entries.map(function (e) { return e.name; });
    const sources = names.filter(function (nm) { return SOURCE_TELL_RE.test(nm); });
    const maps = names.filter(function (nm) { return /\.map$/i.test(nm); });
    const srcDirs = names.filter(function (nm) { return /(^|\/)src\//i.test(nm); });
    const manifests = names.filter(function (nm) { return /(^|\/)(manifest\.json|package\.json|README\.md|tsconfig\.json)$/i.test(nm); });
    const stored = entries.filter(function (e) { return e.method === 0; });
    const reasons = [];
    let score = 0;
    if (sources.length) {
        score += 40;
        reasons.push("容器内直接带有源码文件：" + sources.slice(0, 6).join(", "));
    }
    if (maps.length) {
        score += 25;
        reasons.push("带有 sourcemap：" + maps.slice(0, 4).join(", ") + "（可据此还原原始源码）");
    }
    if (srcDirs.length) {
        score += 15;
        reasons.push("携带 src/ 源码目录（" + srcDirs.length + " 个文件）");
    }
    if (manifests.length) {
        score += 10;
        reasons.push("含元数据/说明文件：" + manifests.slice(0, 6).join(", "));
    }
    if (stored.length) {
        score += 20;
        reasons.push(stored.length + " 个条目为 STORED 未压缩存储，内容可被直接提取");
    }
    else {
        reasons.push("所有条目均为 deflate 压缩；压缩不等于加密，仍可被一键解开");
    }
    const level = score >= 55 ? "high" : (score >= 25 ? "medium" : "low");
    const listed = entries.slice(0, 60).map(function (e) {
        return { name: e.name, method: e.method === 0 ? "stored" : "deflate", compressed_bytes: e.csize, size_bytes: e.usize };
    });
    const previews = [];
    for (let i = 0; i < entries.length && previews.length < ENTRY_READ_LIMIT; i += 1) {
        const e = entries[i];
        if (e.method !== 0 || !isTextFile(e.name)) {
            continue;
        }
        const o = e.localOff;
        if (o + 30 > bytes.length) {
            continue;
        }
        if (!(bytes[o] === 0x50 && bytes[o + 1] === 0x4b && bytes[o + 2] === 0x03 && bytes[o + 3] === 0x04)) {
            continue;
        }
        const nameLen = bytes[o + 26] | (bytes[o + 27] << 8);
        const extraLen = bytes[o + 28] | (bytes[o + 29] << 8);
        const dataStart = o + 30 + nameLen + extraLen;
        const text = bytesToUtf8(bytes.slice(dataStart, dataStart + Math.min(e.csize, 2000)));
        previews.push({ name: e.name, head: text.slice(0, 400) });
    }
    return {
        action: "probe_artifact",
        target: path,
        ok: true,
        container: "zip/toolpkg 容器",
        size_bytes: sizeBytes,
        entries_total: entries.length,
        entries: listed,
        entries_truncated: entries.length > listed.length,
        stored_entry_previews: previews,
        reversibility: { level: level, score: Math.min(score, 100), reasons: reasons },
        message: "已免解压解析压缩容器目录：共 " + entries.length + " 个条目，可逆性评估 " + level + "。若容器内含源码/sourcemap，等价于把实现直接交付给逆向者，发布前应剔除。",
        duration_ms: Date.now() - started,
        disclaimer: DISCLAIMER_ZH
    };
}
async function probeArtifact(path, env) {
    const started = Date.now();
    const exists = await fsExists(path, env);
    if (!exists) {
        return { action: "probe_artifact", target: path, ok: false, message: "文件不存在，请检查路径。", disclaimer: DISCLAIMER_ZH };
    }
    const info = await fsInfo(path, env);
    const segRes = await readSegments(path, env);
    if (!segRes.ok) {
        const asContainer = await probeBinaryContainer(path, env, info, started);
        if (asContainer) {
            return asContainer;
        }
        return { action: "probe_artifact", target: path, ok: false, message: "读取失败：" + (segRes.error || ""), disclaimer: DISCLAIMER_ZH };
    }
    const whole = segRes.segments.map((s) => s.text).join("");
    const sizeBytes = (info && info.size) || whole.length;
    const head = whole.slice(0, 4096);
    let containerType = null;
    let isBinary = false;
    if (/^\s*PK\u0003\u0004/.test(head) || /^\s*PK/.test(head)) {
        containerType = "zip/toolpkg 容器";
        isBinary = true;
    }
    else if (whole.indexOf("\u0000") >= 0 && whole.replace(/\u0000/g, "").length < whole.length * 0.7) {
        isBinary = true;
    }
    if (containerType === "zip/toolpkg 容器" || (isBinary && !TEXT_FILE_RE.test(path))) {
        return {
            action: "probe_artifact",
            target: path,
            ok: true,
            container: containerType || "二进制/非文本文件",
            size_bytes: sizeBytes,
            message: "该文件是打包容器或二进制产物，不能直接做文本探测；请先用解压/反编译手段解开后，再对内部 js/json 执行 scan_source 或 probe_artifact（仅限自有/已授权文件）。",
            duration_ms: Date.now() - started,
            disclaimer: DISCLAIMER_ZH
        };
    }
    const lines = whole.split("\n");
    let maxLineLen = 0;
    let totalLenNoWs = 0;
    for (let i = 0; i < lines.length; i += 1) {
        const l = lines[i].length;
        if (l > maxLineLen) {
            maxLineLen = l;
        }
        totalLenNoWs += l;
    }
    const minified = lines.length > 0 && maxLineLen > 800;
    const avgLine = whole.length / Math.max(1, lines.length);
    const hasMetadata = /\/\*\s*METADATA/.test(whole);
    const hasSourcemap = /\/\/[#@]\s*sourceMappingURL=/i.test(whole);
    const exportNames = [];
    const exportRe = /\bexports\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g;
    let em;
    while ((em = exportRe.exec(whole)) !== null) {
        exportNames.push(em[1]);
    }
    const found = scanText(path, whole);
    const riskMap = {};
    let score = 0;
    for (let i = 0; i < found.length; i += 1) {
        const f = found[i];
        riskMap[f.rule] = (riskMap[f.rule] || 0) + 1;
        score += severityWeight(f.severity);
    }
    const hexLongCount = (whole.match(/\b[0-9a-f]{32,}\b/gi) || []).length;
    const longB64Count = (whole.match(/[A-Za-z0-9+/]{60,}={0,2}/g) || []).length;
    const obfuscated = (whole.match(/_0x[0-9a-f]{4,}/g) || []).length > 10;
    if (minified) {
        score += 12;
    }
    if (obfuscated) {
        score += 20;
    }
    if (hasMetadata) {
        score += 6;
    }
    if (hasSourcemap) {
        score += 25;
    }
    score = Math.min(100, score);
    let level = "低（仍需假设可逆）";
    let levelEn = "low (still assume reversible)";
    if (score >= 50) {
        level = "高（极易被还原/提取信息）";
        levelEn = "high (very easy to reconstruct/extract)";
    }
    else if (score >= 20) {
        level = "中（常规逆向投入即可还原）";
        levelEn = "medium (ordinary reversing effort)";
    }
    const urlHosts = [];
    const hostRe = /https?:\/\/([A-Za-z0-9.\-]+)/g;
    let hm;
    while ((hm = hostRe.exec(whole)) !== null) {
        if (urlHosts.indexOf(hm[1]) < 0 && urlHosts.length < 30) {
            urlHosts.push(hm[1]);
        }
    }
    return {
        action: "probe_artifact",
        target: path,
        ok: true,
        size_bytes: sizeBytes,
        text_lines: lines.length,
        text_chars: whole.length,
        avg_line_len: Math.round(avgLine * 10) / 10,
        max_line_len: maxLineLen,
        minified: minified,
        has_metadata: hasMetadata,
        has_sourcemap: hasSourcemap,
        exported_tools: exportNames.slice(0, 30),
        obfuscated_marker_detected: obfuscated,
        hex_long_strings: hexLongCount,
        long_base64_blocks: longB64Count,
        risk_by_rule: riskMap,
        sample_findings: found.slice(0, 30),
        url_hosts: urlHosts.slice(0, 30),
        reversibility: {
            score: score,
            level_zh: level,
            level_en: levelEn,
            note_zh: "得分越高表示“拿到该产物后”越容易被还原逻辑/提取信息。任何客户端代码都不应被视为不可逆；请将机密放在服务端/宿主侧。",
            note_en: "Higher score means easier reconstruction/info extraction once the artifact is obtained. No client-side code is truly irreversible; keep secrets server-side / host-side."
        },
        duration_ms: Date.now() - started,
        disclaimer: DISCLAIMER_ZH
    };
}
async function makeReport(path, env, maxDepth, maxFiles, maxFindings) {
    const scan = await scanSource(path, env, maxDepth, maxFiles, maxFindings);
    const summary = scan.summary;
    const lines = [];
    lines.push("# 破甲自检 · 加固报告");
    lines.push("");
    lines.push("> " + DISCLAIMER_ZH);
    lines.push("> " + DISCLAIMER_EN);
    lines.push("");
    lines.push("**检测目标**: `" + path + "`  ");
    lines.push("**已扫描文件**: " + summary.scanned_files + "  **风险总数(抽样)**: " + summary.total + "  **耗时**: " + summary.duration_ms + "ms");
    lines.push("");
    lines.push("## 风险分级");
    lines.push("");
    lines.push("- 🔴 高危(high): " + (summary.by_severity.high || 0));
    lines.push("- 🟠 中危(medium): " + (summary.by_severity.medium || 0));
    lines.push("- 🟡 低危/提示(low): " + (summary.by_severity.low || 0));
    lines.push("");
    lines.push("## 按类别统计");
    lines.push("");
    const cats = Object.keys(summary.by_category || {});
    if (cats.length === 0) {
        lines.push("未发现命中项。");
    }
    else {
        for (let i = 0; i < cats.length; i += 1) {
            const c = summary.by_category[cats[i]];
            lines.push("- **" + cats[i] + "**: " + c.total + " (high=" + (c.high || 0) + ", medium=" + (c.medium || 0) + ", low=" + (c.low || 0) + ")");
        }
    }
    lines.push("");
    lines.push("## 代表性风险点");
    lines.push("");
    const findings = scan.findings || [];
    if (findings.length === 0) {
        lines.push("未发现代表性风险点。");
    }
    else {
        const shown = findings.slice(0, 50);
        for (let i = 0; i < shown.length; i += 1) {
            const f = shown[i];
            lines.push("- [" + f.severity.toUpperCase() + "] `" + f.file + ":" + f.line + "` 「" + f.category + "·" + f.label + "」");
            lines.push("  - 命中: " + "`" + f.snippet + "`");
            lines.push("  - 建议: " + f.advice);
        }
    }
    lines.push("");
    lines.push("## 加固检查清单");
    lines.push("");
    for (let i = 0; i < HARDEN_CHECKLIST.length; i += 1) {
        lines.push("- " + HARDEN_CHECKLIST[i]);
    }
    lines.push("");
    lines.push("---");
    lines.push("生成方式：selfguard（纯本地只读静态启发式自检，不联网、不修改文件）。");
    return {
        action: "report",
        target: path,
        summary: summary,
        top_files: scan.top_files,
        checklist: HARDEN_CHECKLIST,
        markdown: lines.join("\n"),
        disclaimer: DISCLAIMER_ZH
    };
}
const PojiaGuard = (function () {
    async function selfguard(params) {
        const action = String((params && params.action) || "scan_source").toLowerCase();
        const path = String((params && params.path) || "").trim();
        const env = String((params && params.environment) || "android").toLowerCase() === "linux" ? "linux" : "android";
        const maxDepth = parseInt(String((params && params.max_depth) || DEFAULT_MAX_DEPTH), 10) || DEFAULT_MAX_DEPTH;
        const maxFiles = parseInt(String((params && params.max_files) || DEFAULT_MAX_FILES), 10) || DEFAULT_MAX_FILES;
        const maxFindings = parseInt(String((params && params.max_findings) || DEFAULT_MAX_FINDINGS), 10) || DEFAULT_MAX_FINDINGS;
        if (!path) {
            return { success: false, message: "缺少参数 path（目标文件或目录）。" };
        }
        try {
            let data;
            if (action === "probe_artifact") {
                data = await probeArtifact(path, env);
            }
            else if (action === "report") {
                data = await makeReport(path, env, maxDepth, maxFiles, maxFindings);
            }
            else {
                data = await scanSource(path, env, maxDepth, maxFiles, maxFindings);
            }
            const total = (data.summary && data.summary.total) || 0;
            return {
                success: true,
                message: (action === "scan_source" ? "源码/目录风险扫描完成" : action === "probe_artifact" ? "产物探测完成" : "加固报告已生成") + "（" + path + "）",
                data: data
            };
        }
        catch (e) {
            return { success: false, message: "执行失败：" + String((e && e.message) || e) };
        }
    }
    return {
        selfguard: selfguard
    };
})();
exports.selfguard = PojiaGuard.selfguard;
