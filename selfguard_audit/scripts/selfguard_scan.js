/*
 * selfguard_audit / scripts/selfguard_scan.js
 * 备用执行脚本：读取同目录 params.json，转发到已安装的 selfguard 沙盒包工具。
 * 运行方式：operit_editor:debug_run_sandbox_script(source_path = 本文件路径)
 */
const SG = { logs: [] };
const SKILL_ROOT = "/sdcard/Download/Operit/skills/selfguard_audit";
const PARAMS_PATH = SKILL_ROOT + "/scripts/params.json";
const DISCLAIMER = "本插件仅用于学习和参考；仅限检测本人拥有或已获得明确授权的工程/产物，禁止用于绕过他人版权、授权、DRM、支付或访问控制。";

function pushLog(message) {
    SG.logs.push(String(message));
}

async function readParams() {
    try {
        const info = await Tools.Files.exists(PARAMS_PATH);
        const ok = !info || info.exists === undefined ? true : !!info.exists;
        if (!ok) {
            pushLog("未找到 " + PARAMS_PATH);
            return {};
        }
        const res = await Tools.Files.read(PARAMS_PATH);
        const text = res && (res.content || res.text || res.data);
        if (!text) {
            pushLog("params.json 读取为空");
            return {};
        }
        return JSON.parse(text);
    } catch (e) {
        pushLog("params.json 解析失败：" + (e && e.message ? e.message : String(e)));
        return {};
    }
}

async function main() {
    const params = await readParams();
    const target = params.path || "";
    if (!target) {
        complete({
            success: false,
            skill: "selfguard_audit",
            message: "缺少 path。请先把 {\"action\":\"scan_source\",\"path\":\"<目标目录>\"} 写入 " + PARAMS_PATH + "，或直接用 use_package(\"selfguard\") 调用 selfguard:selfguard。",
            disclaimer: DISCLAIMER,
            logs: SG.logs
        });
        return;
    }

    const payload = {
        action: params.action || "scan_source",
        path: target,
        environment: params.environment || "android"
    };
    if (params.max_depth) payload.max_depth = params.max_depth;
    if (params.max_files) payload.max_files = params.max_files;
    if (params.max_findings) payload.max_findings = params.max_findings;

    try {
        const result = await toolCall("selfguard:selfguard", payload);
        complete({
            success: true,
            skill: "selfguard_audit",
            via: "selfguard:selfguard",
            params: payload,
            result: result,
            disclaimer: DISCLAIMER,
            logs: SG.logs
        });
    } catch (e) {
        const msg = e && e.message ? e.message : String(e);
        pushLog("转发失败：" + msg);
        complete({
            success: false,
            skill: "selfguard_audit",
            via: "selfguard:selfguard",
            params: payload,
            message: "调用 selfguard:selfguard 失败：" + msg + "。可改用 pojia_guard:pojia_guard，或用 operit_editor:debug_install_js_package(source_path=\"/sdcard/Download/Operit/dev_package/selfguard/selfguard.js\") 重新安装 selfguard 包。",
            disclaimer: DISCLAIMER,
            logs: SG.logs
        });
    }
}

main();
