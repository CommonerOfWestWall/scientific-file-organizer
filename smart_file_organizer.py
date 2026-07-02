from __future__ import annotations

import csv
import calendar
import base64
import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import re
import shutil
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk

import customtkinter as ctk

try:
    from PIL import ExifTags, Image
except Exception:
    ExifTags = None
    Image = None


APP_NAME = "科学文件整理器"
ARCHIVE_MARKER = ".科学整理归档.json"
RULES_FILE = "rules.json"
LOCAL_RULES_FILE = "rules.local.json"
APP_SETTINGS_FILE = "app_settings.json"

RULE_FIELD_LABELS = {
    "important_topics": "重要资料：证件、合同、证明",
    "finance_topics": "财务票据：发票、报销、账单",
    "design_topics": "设计视觉：海报、图标、品牌",
    "dev_topics": "代码开发：源码、构建、脚本",
    "data_topics": "数据表格：报表、台账、备份",
    "stock_topics": "素材来源：素材站、模板站",
    "software_topics": "软件工具：安装包、插件、驱动",
    "model_topics": "3D/CAD：模型、打印、工程",
    "doc_topics": "办公文档：报告、方案、计划",
    "audio_topics": "音频：音乐、音效、录音",
    "screenshot_topics": "截图照片：微信图、截屏、相册",
    "education_topics": "学习科普：课程、教材、论文",
    "marketing_topics": "活动运营：宣传、年会、展会",
    "publishing_topics": "出版图书：书影、版权、上架",
    "fulfillment_topics": "订单物流：发货、库存、结算",
}

AI_PROVIDER_PRESETS = {
    "DeepSeek": "https://api.deepseek.com/v1",
    "通义千问": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "智谱GLM": "https://open.bigmodel.cn/api/paas/v4",
    "Kimi": "https://api.moonshot.cn/v1",
    "硅基流动": "https://api.siliconflow.cn/v1",
    "自定义接口": "",
}

COLORS = {
    "app_bg": ("#f8fafc", "#0f172a"),
    "panel": ("#ffffff", "#111827"),
    "panel_soft": ("#f8fafc", "#1f2937"),
    "card": ("#ffffff", "#182230"),
    "text": ("#101828", "#f9fafb"),
    "muted": ("#667085", "#cbd5e1"),
    "subtle": ("#344054", "#e5e7eb"),
    "blue_soft": ("#eff6ff", "#1e3a8a"),
    "purple_soft": ("#f5f3ff", "#3b0764"),
    "amber_soft": ("#fffbeb", "#451a03"),
    "red_soft": ("#fef2f2", "#450a0a"),
}


@dataclass
class PlanItem:
    source: Path
    destination: Path
    category: str
    confidence: int
    reason: str
    size_bytes: int
    modified_at: datetime
    is_dir: bool


@dataclass
class MoveResult:
    log_path: Path
    rollback_path: Path
    success_count: int
    failure_count: int
    failures: list[tuple[str, str]]
    archive_root: Path


@dataclass
class RecoveryLog:
    path: Path
    archive_root: Path
    item_count: int
    modified_at: datetime


def runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def timestamp_version(prefix: str = "user") -> str:
    return f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _blob_from_bytes(data: bytes) -> DATA_BLOB:
    buffer = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob._buffer = buffer
    return blob


def protect_secret(secret: str) -> str:
    if not secret:
        return ""
    if os.name != "nt":
        return "plain:" + base64.b64encode(secret.encode("utf-8")).decode("ascii")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _blob_from_bytes(secret.encode("utf-8"))
    out_blob = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        return ""
    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return "dpapi:" + base64.b64encode(encrypted).decode("ascii")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def unprotect_secret(value: str) -> str:
    if not value:
        return ""
    if value.startswith("plain:"):
        try:
            return base64.b64decode(value.removeprefix("plain:")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ""
    if not value.startswith("dpapi:") or os.name != "nt":
        return value
    try:
        encrypted = base64.b64decode(value.removeprefix("dpapi:"))
    except ValueError:
        return ""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _blob_from_bytes(encrypted)
    out_blob = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        return ""
    try:
        plain = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return plain.decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def load_app_settings() -> dict:
    defaults = {
        "appearance": "light",
        "ai": {
            "enabled": False,
            "provider": "DeepSeek",
            "base_url": AI_PROVIDER_PRESETS["DeepSeek"],
            "api_key": "",
            "model": "",
        },
    }
    path = runtime_dir() / APP_SETTINGS_FILE
    if not path.exists():
        return defaults
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return defaults
    if not isinstance(data, dict):
        return defaults
    merged = dict(defaults)
    merged.update({k: v for k, v in data.items() if k != "ai"})
    ai = dict(defaults["ai"])
    if isinstance(data.get("ai"), dict):
        ai.update(data["ai"])
    encrypted_key = str(ai.get("api_key_encrypted", ""))
    if encrypted_key:
        ai["api_key"] = unprotect_secret(encrypted_key)
    merged["ai"] = ai
    return merged


def save_app_settings(settings: dict) -> None:
    data = json.loads(json.dumps(settings, ensure_ascii=False))
    ai = data.get("ai")
    if isinstance(ai, dict):
        api_key = str(ai.pop("api_key", ""))
        if api_key:
            ai["api_key_encrypted"] = protect_secret(api_key)
        elif not ai.get("api_key_encrypted"):
            ai["api_key_encrypted"] = ""
    path = runtime_dir() / APP_SETTINGS_FILE
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def split_rule_text(text: str) -> list[str]:
    parts = re.split(r"[\n,，、;；|]+", text)
    return [part.strip() for part in parts if part.strip()]


def join_rule_values(values: list[str] | tuple[str, ...]) -> str:
    return "，".join(values)


class SmartClassifier:
    """A local classifier that combines purpose, file type, source pattern, and batch themes."""
    TOKEN_REGEX = re.compile(r"[a-zA-Z][a-zA-Z0-9]{2,}|[\u4e00-\u9fff]{2,8}")
    DATE_TOKEN_REGEX = re.compile(r"\d{4}[-_年]?\d{0,2}[-_月]?\d{0,2}")
    PROJECT_NOISE_REGEX = re.compile(r"(\d{4}[-_.年]?\d{1,2}[-_.月]?\d{0,2}|\d+\s*[-–]\s*\d+|第?[一二三四五六七八九十\d]+期|[上下]$|副本|copy|CC\s*\(?\d+\.?x?\)?|已转换|已接受修订|修改|改写版|改\d*|最终|终稿|精简版|完整版|英文润色版|英语|加顿号|单页|方向|成片|课件|讲义|习题|封面|配图|脚本|文案|视频素材|素材|AE模板|模板|Report|页面[_\s-]*\d+|图像[_\s-]*\d+)", re.I)
    SPLIT_VOLUME_REGEX = re.compile(r"\.(zip|7z|rar)\.\d{3}$", re.I)
    STOCK_ID_REGEX = re.compile(r"^(iss|ist|pki)[_\d-]", re.I)

    IMPORTANT_TOPICS = (
        "身份证", "护照", "户口", "驾驶证", "驾照", "银行卡", "社保", "医保", "合同",
        "证明", "证书", "简历", "offer", "录取", "档案", "协议", "授权",
    )
    FINANCE_TOPICS = ("银行", "流水", "理财", "税", "个税", "工资", "预算", "报价", "采购", "订单", "发票", "报销", "账单", "收据")
    DESIGN_TOPICS = ("logo", "海报", "封面", "banner", "kv", "视觉", "设计", "ui", "icon", "图标", "插画", "品牌", "画册")
    DEV_TOPICS = ("github", "源码", "代码", "repo", "node_modules", "venv", "src", "dist", "build", "api", "sdk", "debug")
    DATA_TOPICS = ("数据", "dataset", "导出", "统计", "表格", "database", "backup", "备份", "报表", "台账")
    STOCK_TOPICS = ("包图网", "摄图", "站酷", "千图", "素材", "stock", "template", "模板", "vecteezy", "istock", "shutterstock")
    SOFTWARE_TOPICS = ("installer", "setup", "安装", "chromium", "extension", "插件", "驱动", "studio", "hevc", "appxbundle", "模拟器", "修改器", "风灵月影", "yuzu", "ns-emu", "netpass", "cheat", "trainer")
    MODEL_TOPICS = ("3d", "cad", "模型", "手办", "打印", "stl", "3mf", "obj", "glb", "gltf", "bambu")
    DOC_TOPICS = ("说明", "文档", "报告", "方案", "清单", "计划", "教程", "会议", "纪要", "申请", "总结")
    AUDIO_TOPICS = ("音乐", "音效", "歌曲", "合唱", "配乐", "录音", "播客", "voice", "audio")
    SCREENSHOT_TOPICS = ("截图", "截屏", "screenshot", "微信图片", "wx", "img_", "dsc", "photo", "相册")
    EDUCATION_TOPICS = ("课程", "教材", "教案", "课件", "实验", "物理", "化学", "科学", "数学", "语文", "英语", "读书", "阅读", "章节", "第一章", "第二章", "第三章", "第四章", "第五章", "第六章", "第七章", "力", "磁极", "静电", "温度计", "汽化", "液化", "月兔号")
    MARKETING_TOPICS = ("活动", "宣传", "推广", "新书", "推荐", "重阳", "春节", "元旦", "除夕", "读书日", "朋友圈", "欢迎光临", "海报", "招生", "发布会")
    PUBLISHING_TOPICS = (
        "图书", "书名", "书号", "isbn", "书影", "样书", "目录", "版权页", "版权", "内文", "文前", "扉页",
        "封面", "腰封", "详情页", "上架", "网店", "当当", "京东", "天猫", "有赞", "微店", "新书信息",
        "教材", "教科书", "教师用书", "制版", "校对", "终稿", "书展", "书单", "选题", "出版", "出版社",
    )
    FULFILLMENT_TOPICS = (
        "快递单号", "发货单", "拣货单", "订单", "结算", "结算单", "差额处理", "分销", "返款",
        "批量发货", "发出单号", "单号回告", "快递", "发货", "销售", "经营情况", "调书", "调书申请单",
    )
    AI_SOURCE_PATTERNS = (
        ("Gemini生成素材", re.compile(r"^gemini_generated_image", re.I)),
        ("即梦生成素材", re.compile(r"^jimeng-", re.I)),
        ("Midjourney生成素材", re.compile(r"midjourney|^mj_", re.I)),
        ("DALL-E生成素材", re.compile(r"dall[·._ -]?e", re.I)),
        ("StableDiffusion生成素材", re.compile(r"stable.?diffusion|comfyui|sdxl", re.I)),
    )
    AI_CATEGORY_PATTERNS: tuple[tuple[str, re.Pattern[str]]] = ()
    MEDIA_PLATFORM_PATTERNS = (
        ("剪映导出", re.compile(r"jianying|capcut|剪映|lv_|draft_content", re.I)),
        ("OBS录屏", re.compile(r"obs|recording|录屏|屏幕录制|screen.?record", re.I)),
        ("B站下载", re.compile(r"bilibili|b站|哔哩|BV[0-9A-Za-z]{8,}", re.I)),
        ("抖音素材", re.compile(r"douyin|抖音|tiktok", re.I)),
        ("YouTube素材", re.compile(r"youtube|youtu\\.be", re.I)),
        ("微信QQ接收", re.compile(r"wechat|weixin|微信|qq|tim|wx_camera|mmexport", re.I)),
    )

    IMAGE_EXTS = {".jpg", ".jpeg", ".jfif", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".raw", ".eps", ".ico"}
    VIDEO_EXTS = {".mp4", ".mov", ".mkv", ".avi", ".rmvb", ".wmv", ".flv", ".webm", ".m4v", ".mxf", ".m3u8"}
    AUDIO_EXTS = {".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".wma", ".aiff"}
    MODEL_EXTS = {".stl", ".3mf", ".obj", ".glb", ".gltf", ".fbx", ".blend", ".step", ".stp", ".iges", ".igs", ".dwg", ".dxf"}
    DOC_EXTS = {".doc", ".docx", ".pdf", ".txt", ".md", ".ppt", ".pptx", ".rtf", ".pages", ".key"}
    CODE_EXTS = {".py", ".pyw", ".spec", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".json", ".ini", ".toml", ".yaml", ".yml", ".ps1", ".bat", ".command", ".sh", ".sql", ".cs", ".xaml", ".csproj", ".sln", ".pyproj", ".props", ".targets", ".resx"}
    INSTALLER_EXTS = {".exe", ".msi", ".appx", ".appxbundle", ".crx", ".dmg", ".pkg", ".deb", ".rpm"}
    ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
    AI_MODEL_EXTS = {".safetensors", ".ckpt", ".pth", ".pt", ".onnx"}
    DATA_EXTS = {".csv", ".tsv", ".xlsx", ".xls", ".numbers", ".db", ".sqlite", ".parquet", ".xml", ".jsonl", ".sav"}
    FONT_EXTS = {".ttf", ".otf", ".woff", ".woff2", ".eot"}
    DESIGN_EXTS = {".psd", ".psb", ".ai", ".fig", ".sketch", ".xd", ".indd", ".svg", ".ase", ".afdesign"}
    EBOOK_EXTS = {".epub", ".mobi", ".azw3", ".chm"}
    PROJECT_BUNDLE_EXTS = {".aep", ".prproj", ".drp", ".drx"}
    POST_EXTS = {".aep", ".prproj", ".drp", ".drx", ".xmp", ".srt", ".ass", ".vtt", ".sample"}
    POST_CACHE_EXTS = {".cfa", ".pek"}
    DEV_ARTIFACT_EXTS = {".pyc", ".pyd", ".pyz", ".dll", ".toc", ".vsidx", ".cache", ".suo", ".pdb", ".resources", ".tcl", ".enc", ".msg", ".tm", ".typed", ".tmpl", ".dat", ".v2", ".user", ".manifest", ".res"}
    EMAIL_EXTS = {".msg", ".eml"}
    DISC_IMAGE_EXTS = {".bin", ".img", ".iso", ".cue", ".mdf", ".mds", ".nrg", ".dvd", ".dvds"}
    SHORTCUT_TEMP_EXTS = {".lnk", ".url", ".xdown", ".download", ".tmp", ".part", ".crdownload", ".torrent"}
    SKIP_NAMES = {"$recycle.bin", "system volume information", "desktop.ini", "thumbs.db", ".ds_store"}
    GENERIC_PROJECT_DIRS = {
        "01_内容项目", "02_ai生成素材_按来源与月份", "04_商用素材库", "05_影视音频资料", "07_文档脚本流程与字体",
        "08_旧文件夹与未归类", "10_设计与品牌资产", "11_数据表格与备份", "13_照片截图与临时影像",
        "其他创作素材", "待识别文件夹", "其他散件", "压缩包待识别", "视频", "图片", "素材", "整理", "视频文案",
        "文档脚本流程", "代码配置与自动化脚本", "设计源文件与视觉素材", "视频图片素材", "音乐音效合集",
        "普通图片素材", "平台接收与下载图片", "微信qq接收", "即梦生成素材", "gemini生成素材",
    }
    SHORT_PROJECT_BLOCKLIST = {
        "力学", "素材", "视频", "图片", "文档", "脚本", "模板", "封面", "配图", "音频", "录音", "截图",
        "微信图片", "qq截图", "录屏", "输出", "拍摄", "预览", "下载", "合同", "发票", "报价单", "会议纪要",
        "标题", "视频样机图",
    }
    GENERIC_PROJECT_ALIAS_PATTERNS = (
        (re.compile(r".*(25总结|2025总结|2025年度总结).*", re.I), "2025年度总结"),
        (re.compile(r".*(watermark|批量.*水印|加水印).*", re.I), "批量水印工具"),
        (re.compile(r".*(片头.*片尾|intro.*outro).*", re.I), "视频片头片尾工具"),
        (re.compile(r".*(book.*3d|图书.*3d|书籍.*3d).*", re.I), "图书3D生成工具"),
    )

    STOP_WORDS = {
        "copy", "final", "new", "old", "test", "demo", "backup", "download", "image", "images", "video",
        "file", "project", "untitled", "未命名", "项目", "素材", "图片", "视频", "文件", "新建",
        "副本", "最终", "测试", "下载", "压缩包", "安装包", "使用", "说明", "版本",
        "新建文本文档", "文本文档", "新建文本", "未命名项目",
        "and", "the", "with", "from", "for", "plus", "black", "white", "x64", "x86",
        "iss", "ist", "pki", "pose", "dall", "imageinput", "category",
        "目录", "文前", "内文", "扉页", "版权", "版权页", "扫描文稿", "归档", "技术", "申请",
        "报告", "清单", "证明", "材料", "资料", "详情", "详情页", "新书信息", "上架信息",
    }

    def __init__(self, rules_path: Path | None = None, rules_data: dict | None = None) -> None:
        # ── 内嵌兜底规则（PyInstaller 打包进 EXE） ──────────────
        self._builtin_rules = self._load_builtin_rules()

        # ── 外部规则路径（EXE 同级 / 脚本同级） ────────────────
        if rules_path:
            self.rules_path = rules_path
        elif getattr(sys, "frozen", False):
            self.rules_path = Path(sys.executable).with_name(RULES_FILE)
        else:
            self.rules_path = Path(__file__).with_name(RULES_FILE)
        self.effective_rules: dict = {}
        self.rules_hash = ""
        self.rules_version = ""
        if rules_data is not None:
            self._apply_rules(rules_data)
        else:
            self._load_external_rules()

    def _load_builtin_rules(self) -> dict | None:
        """尝试从 PyInstaller 内嵌数据 或包内资源加载兜底 rules.json。"""
        try:
            # PyInstaller 打包后，资源释放到 sys._MEIPASS
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                bundled = Path(sys._MEIPASS) / RULES_FILE
            else:
                bundled = Path(__file__).parent / RULES_FILE
            if bundled.exists():
                return json.loads(bundled.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _load_external_rules(self) -> None:
        """加载外部 rules.json，与内嵌规则合并；外部优先覆盖。"""
        rules: dict = {}
        # 先以内嵌规则为基底
        if self._builtin_rules:
            rules.update(self._builtin_rules)
        # 再用外部规则覆盖
        for candidate in (self.rules_path, self.rules_path.with_name(LOCAL_RULES_FILE)):
            if not candidate.exists():
                continue
            try:
                external = json.loads(candidate.read_text(encoding="utf-8"))
                rules = self._merge_rules(rules, external)
            except (OSError, json.JSONDecodeError):
                pass
        self._apply_rules(rules)

    @staticmethod
    def _merge_rules(base: dict, override: dict) -> dict:
        merged = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                nested = dict(merged[key])
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, list) and isinstance(nested.get(sub_key), list):
                        nested[sub_key] = SmartClassifier._merge_rule_lists(nested[sub_key], sub_value)
                    else:
                        nested[sub_key] = sub_value
                merged[key] = nested
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = SmartClassifier._merge_rule_lists(merged[key], value)
            else:
                merged[key] = value
        return merged

    @staticmethod
    def _merge_rule_lists(base: list, extra: list) -> list:
        result = []
        seen = set()
        for item in [*base, *extra]:
            try:
                marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            except TypeError:
                marker = repr(item)
            if marker in seen:
                continue
            seen.add(marker)
            result.append(item)
        return result

    def _apply_rules(self, rules: dict) -> None:
        if not rules:
            self.effective_rules = {}
            self.rules_hash = ""
            self.rules_version = ""
            return
        self.effective_rules = rules
        self.rules_hash = self._rules_hash(rules)
        self.rules_version = str(rules.get("version", ""))
        for key, value in rules.get("keywords", {}).items():
            attr = key.upper()
            if hasattr(self, attr):
                setattr(self, attr, tuple(value))
        for key, value in rules.get("extensions", {}).items():
            attr = key.upper()
            if hasattr(self, attr):
                setattr(self, attr, {ext.lower() for ext in value})
        if "stop_words" in rules:
            self.STOP_WORDS = set(rules["stop_words"])
        if "skip_names" in rules:
            self.SKIP_NAMES = {name.lower() for name in rules["skip_names"]}
        patterns = []
        for item in rules.get("ai_source_patterns", []):
            try:
                patterns.append((item["name"], re.compile(item["pattern"], re.I)))
            except (KeyError, re.error):
                continue
        if patterns:
            self.AI_SOURCE_PATTERNS = tuple(patterns)
        category_patterns = []
        for item in rules.get("ai_category_patterns", []):
            try:
                category = str(item["category"]).strip().strip("/\\")
                if category and not category.startswith("99_"):
                    category_patterns.append((category, re.compile(str(item["pattern"]), re.I)))
            except (KeyError, re.error):
                continue
        self.AI_CATEGORY_PATTERNS = tuple(category_patterns)

    @staticmethod
    def _rules_hash(rules: dict) -> str:
        payload = json.dumps(rules, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def classify(self, path: Path, theme: str | None = None) -> str:
        return self.classify_detailed(path, theme)[0]

    def classify_detailed(self, path: Path, theme: str | None = None) -> tuple[str, int, str]:
        name = path.name
        lower = name.lower()
        ext = path.suffix.lower()
        modified_month = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m")

        if path.is_dir():
            return self._classify_folder(path, theme)

        if name.lower() in self.SKIP_NAMES or name.startswith("~$") or name.startswith("._"):
            return self._result("98_快捷方式与下载残留/系统缓存与临时文件", 82, "识别为系统索引、缩略图、Office 临时文件或隐藏缓存")

        if ext in self.SHORTCUT_TEMP_EXTS:
            return self._result("98_快捷方式与下载残留", 70, "像快捷方式、浏览器下载残留或临时下载文件")

        if self._is_dev_build_artifact(path):
            return self._result("07_开发代码与自动化/构建产物与运行依赖", 86, "识别为编译缓存、打包产物、运行依赖或 IDE 索引文件")

        if self.SPLIT_VOLUME_REGEX.search(lower):
            return self._result("90_压缩包与待解包/分卷压缩包", 70, "识别为分卷压缩包的一部分")

        if ext in self.DISC_IMAGE_EXTS:
            return self._result("08_软件安装包与插件/光盘镜像与安装介质", 78, "识别为光盘镜像、DVD 工程或安装介质文件")

        if ext in {".pszlpack", ".tb"} or self._has_any(lower, ("photoshop", "blender")):
            return self._result("03_设计与创意资产/设计软件包与页面素材", 78, "像设计软件资源包、页面模板或创作工具资产")

        if self.STOCK_ID_REGEX.match(lower) or "vecteezy" in lower:
            return self._result("04_素材库/商用图片视频素材", 88, "识别为素材站编号或素材站下载文件")

        if ext in self.AI_MODEL_EXTS or self._has_any(lower, ("lora", "loar", "pony", "sdxl", "sd15", "vae", "embedding", "checkpoint", "controlnet")):
            return self._result("02_图片视频与AI素材/AI模型与工作流资源", 92, "命中 AI 模型、LoRA、VAE、Checkpoint 或相关资源特征")

        project_result = self._classify_project_item(path, modified_month, theme)
        if project_result:
            return project_result

        for source_name, pattern in self.AI_SOURCE_PATTERNS:
            if pattern.search(name):
                return self._result(f"02_图片视频与AI素材/AI生成素材/{source_name}/{modified_month}", 96, f"识别到 {source_name} 的命名模式，并按月份归档")

        media_result = self._classify_media_deep(path, modified_month)
        if media_result:
            return media_result

        for category, pattern in self.AI_CATEGORY_PATTERNS:
            if pattern.search(name):
                return self._result(category, 88, "命中 AI 复核后保存的本机规则")

        if ext in self.INSTALLER_EXTS or ext in {".apk", ".ipa", ".qlplugin", ".diagcab", ".cmd"} or self._has_any(lower, self.SOFTWARE_TOPICS):
            return self._result("08_软件安装包与插件", 92, "扩展名或名称显示为安装程序、驱动或浏览器插件")

        code_project = self._code_project_topic(name, theme)
        if code_project and ext in self.CODE_EXTS:
            return self._result(f"07_开发代码与自动化/项目脚本/{code_project}", 88, f"代码脚本命中“{code_project}”项目线索，避免混入通用脚本")

        if ext in self.CODE_EXTS or self._has_any(lower, self.DEV_TOPICS):
            return self._result("07_开发代码与自动化/代码配置脚本", 88, "命中代码、配置、构建或自动化脚本特征")

        if ext in self.POST_CACHE_EXTS or self._has_post_context(path):
            if ext in (self.IMAGE_EXTS | self.VIDEO_EXTS | self.AUDIO_EXTS):
                return self._result("12_剪辑工程与后期制作/模板素材与渲染序列", 84, "父级目录像 AE/PR/剪辑模板，媒体文件按后期素材归档")
            if ext in self.POST_CACHE_EXTS:
                return self._result("12_剪辑工程与后期制作/预览缓存与峰值文件", 82, "识别为 Premiere/剪辑软件生成的音频预览或峰值缓存")

        if ext in self.POST_EXTS:
            return self._result("12_剪辑工程与后期制作/工程字幕调色文件", 88, "命中剪辑、字幕、调色或后期工程扩展名")

        if ext in self.DESIGN_EXTS or self._has_any(lower, self.DESIGN_TOPICS):
            return self._result("03_设计与创意资产/设计源文件与视觉素材", 88, "命中设计源文件扩展名或视觉设计关键词")

        if ext in self.MODEL_EXTS or self._has_any(lower, self.MODEL_TOPICS):
            if ext in self.ARCHIVE_EXTS:
                return self._result("09_3D_CAD与打印模型/模型压缩包", 90, "命中 3D/CAD/打印模型线索且是压缩包")
            return self._result("09_3D_CAD与打印模型/模型文件与工程", 92, "命中 3D/CAD/打印模型扩展名或关键词")

        if self._has_any(lower, self.STOCK_TOPICS):
            if ext in self.AUDIO_EXTS or self._has_any(lower, self.AUDIO_TOPICS):
                return self._result("04_素材库/商用音乐音效", 90, "命中素材来源，同时像音乐或音效")
            return self._result("04_素材库/商用图片视频模板", 88, "命中素材站、模板或商用素材关键词")

        if self._is_person_profile_pdf(name, ext):
            return self._result("05_重要资料/人员资料与证件", 82, "像姓名命名的人员 PDF，保守归入人员资料")

        if self._has_any(lower, self.FULFILLMENT_TOPICS):
            return self._result("10_数据表格与备份/电商订单与发货台账", 90, "命中快递单号、发货、订单、结算或分销线索")

        office_result = self._classify_office_deep(path, modified_month, theme)
        if office_result:
            return office_result

        if ext in self.AUDIO_EXTS or self._has_any(lower, self.AUDIO_TOPICS):
            return self._result(f"11_音频视频资料/音乐音效与录音/{modified_month}", 84, "扩展名或名称显示为音频素材")

        if self._has_any(lower, self.PUBLISHING_TOPICS):
            if ext in self.ARCHIVE_EXTS:
                return self._result("01_出版项目资料/图书上架与宣传包", 84, "压缩包命中图书出版、上架、网店或宣传线索")
            if ext in self.IMAGE_EXTS or ext in self.DESIGN_EXTS:
                return self._result("01_出版项目资料/封面书影与详情素材", 86, "命中书影、封面、详情页、版权页或图书视觉素材线索")
            return self._result("01_出版项目资料/书稿版权与上架资料", 86, "命中图书出版、版权、目录、内文、上架或网店线索")

        if self._has_any(lower, self.EDUCATION_TOPICS):
            return self._result("01_主题项目资料/教育课程与科普素材", 86, "命中课程、教材、实验、章节或科普主题词")

        if self._has_any(lower, self.MARKETING_TOPICS):
            return self._result("01_主题项目资料/宣传活动与运营物料", 84, "命中活动、宣传、新书、节庆或运营物料主题词")

        if self._has_any(lower, self.FINANCE_TOPICS):
            return self._result("05_重要资料/财务票据与报销", 91, "命中发票、报销、账单、工资、税务等财务线索")

        if self._has_any(lower, self.IMPORTANT_TOPICS):
            return self._result("05_重要资料/证件合同与证明", 90, "命中证件、合同、证明、简历或协议等重要资料线索")

        if ext in self.FONT_EXTS or "字体" in name or "font" in lower:
            return self._result("06_办公文档与学习/字体资源", 92, "命中字体扩展名或字体关键词")

        if ext in self.DATA_EXTS or self._has_any(lower, self.DATA_TOPICS):
            return self._result(f"10_数据表格与备份/数据导出与表格/{modified_month}", 86, "命中数据、表格、导出或备份线索")

        if ext in self.EBOOK_EXTS:
            return self._result("06_办公文档与学习/电子书与学习资料", 88, "命中电子书扩展名")

        if ext in self.EMAIL_EXTS:
            return self._result("06_办公文档与学习/邮件与沟通记录", 82, "识别为邮件或沟通记录文件")

        if theme and ext in self.DOC_EXTS:
            return self._result(f"01_主题项目资料/{self._clean_topic(theme)}", 84, f"同批文件反复出现“{theme}”，按共同主题聚合")

        if ext in self.VIDEO_EXTS:
            return self._result(f"11_音频视频资料/视频文件/{modified_month}", 78, "视频文件未命中特定项目，按月份归档")

        if ext in self.IMAGE_EXTS:
            if self._has_any(lower, self.SCREENSHOT_TOPICS):
                return self._result(f"02_图片视频与AI素材/照片截图/{modified_month}", 78, "像照片或截图，按月份归档便于回忆")
            return self._result(f"02_图片视频与AI素材/普通图片素材/{modified_month}", 74, "图片未命中特定项目，按普通素材和月份归档")

        if ext in self.DOC_EXTS or self._has_any(lower, self.DOC_TOPICS):
            return self._result(f"06_办公文档与学习/普通文档资料/{modified_month}", 80, "命中文档、报告、方案或办公文件类型")

        if ext in self.ARCHIVE_EXTS:
            archive_text = " ".join([lower, *(part.lower() for part in path.parts[-5:-1])])
            if theme:
                return self._result(f"01_主题项目资料/{self._clean_topic(theme)}/压缩包", 72, f"压缩包与同批主题“{theme}”相关")
            if self._has_any(archive_text, ("手写", "抠完了的字", "字体", "书法", "毛笔字", "字包")):
                return self._result("03_设计与创意资产/手写字与排版素材包", 78, "压缩包名称像手写字、字体或排版素材集合")
            if self._has_any(archive_text, self.PUBLISHING_TOPICS):
                return self._result("01_出版项目资料/图书上架与宣传包", 78, "压缩包名称命中书影、图书、版权、上架或出版线索")
            if self._has_any(archive_text, self.EDUCATION_TOPICS):
                return self._result("01_主题项目资料/教育课程与科普素材/资料包", 76, "压缩包名称命中课程、科普、教材或实验线索")
            if self._has_any(archive_text, self.MARKETING_TOPICS):
                return self._result("01_主题项目资料/宣传活动与运营物料/资料包", 76, "压缩包名称命中活动、宣传、年会或运营物料线索")
            if self._has_any(archive_text, ("图片", "图像", "照片", "素材", "书影", "插图", "配图")):
                return self._result("02_图片视频与AI素材/图片素材压缩包", 74, "压缩包名称像图片、素材或配图集合")
            return self._result("90_压缩包与待解包", 60, "压缩包缺少明确主题线索，先保守放入待解包区")

        return self._result("99_待确认/其他散件", 45, "没有足够线索，保守放入待确认区")

    def _classify_folder(self, path: Path, theme: str | None) -> tuple[str, int, str]:
        name = path.name
        lower = name.lower()

        if lower in self.SKIP_NAMES:
            return self._result("99_待确认/系统目录", 40, "系统目录，不建议整理")

        library_result = self._classify_library_folder(path)
        if library_result:
            return library_result

        if lower in {"download", "115download", "video", "thumb_cache"}:
            return self._result("98_快捷方式与下载残留/下载缓存目录", 68, "像下载器、缓存或通用视频临时目录")

        if lower in {"programs", "appgallery"} or self._has_any(lower, ("download", "manager", "工具", "program", "gallery")):
            return self._result("08_软件安装包与插件/工具软件目录", 76, "文件夹名像下载器、管理器或工具软件")

        if lower == "x64" or self._has_any(lower, ("yuzu", "模拟器", "修改器", "风灵月影", "black.myth", "wukong", "netpass", "ns-emu")):
            return self._result("08_软件安装包与插件/游戏工具与模拟器", 86, "文件夹名像模拟器、修改器或游戏辅助工具")

        if lower == "compressed":
            return self._result("90_压缩包与待解包/压缩包集合目录", 70, "文件夹名显示为压缩文件集合")

        if "fireshot" in lower:
            return self._result("02_图片视频与AI素材/网页截图与采集", 76, "文件夹名像网页截图工具生成目录")

        if lower.endswith(".pszlpack"):
            return self._result("03_设计与创意资产/设计软件包与页面素材", 78, "像设计软件资源包、页面模板或创作工具资产")

        if self._is_post_sidecar_dir(path):
            return self._result("12_剪辑工程与后期制作/工程包与项目目录", 90, "识别为 AE/PR 工程的同级素材目录，需跟工程文件放在一起")

        if self._is_post_project_dir(path):
            return self._result("12_剪辑工程与后期制作/工程包与项目目录", 92, "识别为 AE/PR/剪辑工程包，需整体保留素材路径关系")

        project_result = self._classify_project_item(path, datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m"), theme)
        if project_result:
            return project_result

        if re.match(r"^(dist|release|publish|output|out)[_-]?", lower) and self._folder_has_ext(path, self.INSTALLER_EXTS | {".exe", ".msi"}):
            return self._result("08_软件安装包与插件/构建发布包目录", 88, "文件夹名像 dist/release，且内部包含 exe/msi 等发布产物")

        if lower in {"dall", "chatgpt", "chatgpt作图"} or re.search(r"dall[·._ -]?e|chatgpt|comfyui|sdxl", lower):
            return self._result("02_图片视频与AI素材/AI生成素材目录", 90, "文件夹名显示为 AI 作图或 AI 生成素材")

        if lower in {"vecteezy", "iss", "ist", "pki"}:
            return self._result("04_素材库/商用图片视频素材", 88, "文件夹名像素材站来源或素材编号集合")

        if self._has_any(lower, self.DEV_TOPICS) or self._folder_has_any(path, {"package.json", "pyproject.toml", ".git"}):
            return self._result("07_开发代码与自动化/项目源码目录", 88, "文件夹名或内部结构像代码项目")
        if self._has_any(lower, self.DESIGN_TOPICS):
            return self._result("03_设计与创意资产/设计项目目录", 84, "文件夹名命中设计或品牌资产线索")
        if self._has_any(lower, self.FULFILLMENT_TOPICS):
            return self._result("10_数据表格与备份/电商订单与发货台账", 90, "文件夹名命中快递单号、发货、订单或结算线索")
        if self._has_any(lower, self.PUBLISHING_TOPICS):
            return self._result("01_出版项目资料/图书项目目录", 88, "文件夹名命中图书出版、书影、上架、网店或版权线索")
        if self._has_any(lower, self.EDUCATION_TOPICS):
            return self._result("01_主题项目资料/教育课程与科普素材", 86, "文件夹名命中课程、实验、章节或科普主题词")
        if self._has_any(lower, self.MARKETING_TOPICS):
            return self._result("01_主题项目资料/宣传活动与运营物料", 84, "文件夹名命中活动、宣传或运营物料线索")
        if self._has_any(lower, self.MODEL_TOPICS):
            return self._result("09_3D_CAD与打印模型/模型项目目录", 88, "文件夹名命中 3D/CAD/打印模型线索")
        if self._has_any(lower, self.STOCK_TOPICS):
            return self._result("04_素材库/商用素材目录", 86, "文件夹名命中素材站或素材库线索")
        for category, pattern in self.AI_CATEGORY_PATTERNS:
            if pattern.search(name):
                return self._result(category, 86, "命中 AI 复核后保存的本机规则")
        if self._has_any(lower, self.FINANCE_TOPICS):
            return self._result("05_重要资料/财务票据与报销", 90, "文件夹名命中财务票据线索")
        if self._has_any(lower, self.IMPORTANT_TOPICS):
            return self._result("05_重要资料/证件合同与证明", 88, "文件夹名命中重要资料线索")
        folder_kind = self._dominant_folder_kind(path)
        if folder_kind:
            return folder_kind
        if theme:
            return self._result(f"01_主题项目资料/{self._clean_topic(theme)}", 80, f"文件夹名与同批主题“{theme}”相关")
        if re.fullmatch(r"images_\d+", lower) or re.fullmatch(r"[a-z]{20,}", lower):
            return self._result("99_待确认/历史下载目录", 58, "像浏览器或工具生成的历史下载目录")
        return self._result("99_待确认/待识别文件夹", 45, "文件夹名和内部结构缺少明确线索")

    def _classify_library_folder(self, path: Path) -> tuple[str, int, str] | None:
        lower = path.name.lower()
        child_hint = self._folder_child_name_hint(path) if re.fullmatch(r"\d{1,4}", lower) else ""
        numbered_text = f"{lower} {child_hint}".lower()
        if child_hint:
            if self._has_any(numbered_text, ("报告会", "会议", "活动", "颁奖", "发布会")) and self._has_any(numbered_text, ("照片", "合影", "影像")):
                return self._result("01_主题项目资料/会议活动照片资料", 84, "编号文件夹内部像会议、报告会或活动照片资料，应按事件资料保留")
            if self._has_any(numbered_text, ("听力", "课程", "小学", "病例", "教学", "培训", "videos", "video", "cd", "dvd", ".dvds")):
                return self._result("11_音频视频资料/教学与光盘视频资料", 82, "编号文件夹内部像教学视频、课程 CD/DVD 或历史影像资料")
            if self._has_any(numbered_text, ("照片", "图片", "影像")):
                return self._result("02_图片视频与AI素材/照片影像资料库", 78, "编号文件夹内部主要像照片或影像资料")
        if "勿删" in path.name or "不要删" in path.name or "备份" in lower:
            return self._result("06_历史资料库/需保留原结构", 94, "文件夹名明确提示保留或备份，不建议拆分整理")
        if re.search(r"\d{4}.*\d{4}.*(排版|图书|资料|文件)", path.name):
            return self._result("06_历史资料库/排版出版老资料", 92, "文件夹名像跨年度历史排版或出版资料库，应保留原结构")
        if "ae工程" in lower or "pr工程" in lower or "工程文件" in lower:
            return self._result("12_剪辑工程与后期制作/工程库", 92, "文件夹名像 AE/PR/剪辑工程库，应整体保留素材路径关系")
        if "ps笔刷" in lower or "笔刷" in lower:
            return self._result("03_设计与创意资产/笔刷字体与插件", 88, "文件夹名像 Photoshop 笔刷、字体或设计插件资源")
        if "光盘镜像" in lower or lower in {"iso", "镜像"}:
            return self._result("08_软件安装包与插件/光盘镜像与安装介质", 88, "文件夹名像光盘镜像或安装介质")
        if "有赞" in lower or self._has_any(lower, ("网店", "店铺页面", "详情页", "商城页面")):
            return self._result("01_出版项目资料/电商页面与详情素材", 86, "文件夹名像网店页面、商品详情或电商素材")
        if lower in {"日常工作", "工作资料", "日常资料"}:
            return self._result("06_历史资料库/日常工作资料", 82, "文件夹名像长期积累的工作资料库，保守保留为资料库")
        if lower in {"素材", "素材库", "资源库"}:
            return self._result("04_素材库/综合素材库", 88, "文件夹名就是素材库，适合按素材库整体保留")
        return None

    def _folder_child_name_hint(self, path: Path, limit: int = 10) -> str:
        names: list[str] = []
        try:
            for child in path.iterdir():
                lower = child.name.lower()
                if lower in self.SKIP_NAMES or child.name.startswith(".") or child.name.startswith("~$"):
                    continue
                names.append(child.name)
                if len(names) >= limit:
                    break
        except OSError:
            return ""
        return " ".join(names)

    def _dominant_folder_kind(self, path: Path) -> tuple[str, int, str] | None:
        counts = {"media": 0, "docs": 0, "code": 0, "design": 0, "model": 0, "audio": 0, "data": 0, "installer": 0, "archive": 0}
        checked = 0
        try:
            for child in path.rglob("*"):
                if not child.is_file():
                    continue
                ext = child.suffix.lower()
                checked += 1
                if ext in self.IMAGE_EXTS or ext in self.VIDEO_EXTS:
                    counts["media"] += 1
                if ext in self.AUDIO_EXTS:
                    counts["audio"] += 1
                if ext in self.DOC_EXTS:
                    counts["docs"] += 1
                if ext in self.CODE_EXTS:
                    counts["code"] += 1
                if ext in self.DESIGN_EXTS:
                    counts["design"] += 1
                if ext in self.POST_EXTS:
                    counts["media"] += 1
                if ext in self.MODEL_EXTS:
                    counts["model"] += 1
                if ext in self.DATA_EXTS:
                    counts["data"] += 1
                if ext in self.INSTALLER_EXTS or ext in {".apk", ".ipa", ".cmd", ".diagcab"}:
                    counts["installer"] += 1
                if ext in self.ARCHIVE_EXTS or re.search(r"\.(zip|7z|rar)\.\d{3}$", child.name.lower()):
                    counts["archive"] += 1
                if checked >= 80:
                    break
        except OSError:
            return None
        if checked < 1:
            return None
        dominant = max(counts, key=counts.get)
        if counts[dominant] / checked < 0.55:
            return None
        lower = path.name.lower()
        if dominant == "media" and self._has_any(lower, ("视频", "video", "videos", "demo", "dvd", "cd")):
            return self._result("11_音频视频资料/视频资料库", 78, "内部以视频为主，且文件夹名像视频、演示或光盘资料库")
        mapping = {
            "media": ("02_图片视频与AI素材/图片视频目录", "内部以图片/视频为主"),
            "audio": ("11_音频视频资料/音乐音效与录音", "内部以音频文件为主"),
            "docs": ("06_办公文档与学习/文档资料目录", "内部以文档资料为主"),
            "code": ("07_开发代码与自动化/代码脚本目录", "内部以代码脚本为主"),
            "design": ("03_设计与创意资产/设计源文件目录", "内部以设计源文件为主"),
            "model": ("09_3D_CAD与打印模型/模型工程目录", "内部以模型文件为主"),
            "data": ("10_数据表格与备份/数据目录", "内部以数据表格为主"),
            "installer": ("08_软件安装包与插件/工具软件目录", "内部以安装包、脚本或工具文件为主"),
            "archive": ("90_压缩包与待解包/压缩包集合目录", "内部以压缩包为主"),
        }
        category, reason = mapping[dominant]
        return self._result(category, 76, reason)

    def _classify_project_item(self, path: Path, modified_month: str, theme: str | None = None) -> tuple[str, int, str] | None:
        project = self._project_name_from_context(path, theme)
        if not project:
            return None
        role = self._project_role(path, project)
        return self._result(f"01_项目工作区/{project}/{role}", 90, f"识别为“{project}”项目资料，按项目优先归档，项目内再按资料角色分层")

    def _project_name_from_context(self, path: Path, theme: str | None = None) -> str | None:
        text = " ".join([path.name.lower(), *(part.lower() for part in path.parts[-4:-1])])
        if self._has_any(text, ("包图网", "ibaotu", "摄图", "站酷", "千图", "vecteezy", "istock", "shutterstock")):
            return None

        generic_project = self._generic_project_from_context(path)
        if generic_project:
            return generic_project

        if theme:
            cleaned = self._normalize_project_topic(theme)
            if self._looks_like_project_topic(cleaned):
                return cleaned

        if path.is_dir() and self._is_project_like_folder(path):
            return self._normalize_project_topic(path.name)

        if path.suffix.lower() in self.CODE_EXTS | self.INSTALLER_EXTS and self._has_any(text, ("工具", "生成器", "generator", "converter", "watermark")):
            return self._normalize_project_topic(path.stem)
        return None

    def _generic_project_from_context(self, path: Path) -> str | None:
        candidates = [path.stem]
        candidates.extend(reversed(path.parts[-5:-1]))
        for candidate in candidates:
            normalized = self._normalize_project_topic(candidate)
            normalized = self._strip_project_noise(normalized)
            if self._looks_like_content_project(normalized):
                return normalized
        return None

    def _normalize_project_topic(self, topic: str) -> str:
        cleaned = self._clean_topic(topic)
        cleaned = re.sub(r"^(改好的|修改后|新版|最终版|换一个ai写的|ai写的|ai改的)[_-]?", "", cleaned, flags=re.I).strip(" ._-")
        data_match = re.search(r"(.{2,}?数据)(库|集)", cleaned)
        if data_match:
            return self._clean_topic(data_match.group(1) + "库")
        if "朗诵" in cleaned and ("片头" in cleaned or "片尾" in cleaned):
            return "朗诵节目"
        for pattern, alias in self.GENERIC_PROJECT_ALIAS_PATTERNS:
            if pattern.match(cleaned):
                return alias
        cleaned = re.sub(r"^\d+[.、_-]?", "", cleaned).strip(" ._-")
        lower = cleaned.lower()
        return cleaned

    def _strip_project_noise(self, topic: str) -> str:
        topic = self.PROJECT_NOISE_REGEX.sub("", topic)
        topic = re.sub(r"(?<=[\u4e00-\u9fff])\d+$", "", topic)
        topic = re.sub(r"[-_（(]?\d+[）)]?$", "", topic)
        topic = re.sub(r"[-_][\u4e00-\u9fff]{1,3}$", "", topic)
        topic = re.sub(r"[_\-\s（）()]+$", "", topic).strip(" ._-（）()")
        topic = re.sub(r"^(【[^】]+】|包图网[_-]?\d+)", "", topic).strip(" ._-")
        return self._clean_topic(topic)

    @staticmethod
    def _looks_like_project_topic(topic: str) -> bool:
        weak_topics = {"共同主题", "生成", "最终", "版本", "精简版", "图解版", "完整", "改进版", "清晰版", "紧凑版", "说明", "文档", "模板"}
        if not topic or topic in weak_topics:
            return False
        if re.fullmatch(r"(wechat|weixin|qq|tim|img|dsc|pxl|copy|screenrecording|screen recording).*", topic.lower()):
            return False
        if re.fullmatch(r"[a-f0-9]{12,}.*", topic.lower()):
            return False
        if any(keyword in topic.lower() for keyword in ("工具", "生成器", "项目", "工程", "口播", "图解", "watermark", "generator", "converter")):
            return True
        return len(topic) >= 5

    def _looks_like_content_project(self, topic: str) -> bool:
        if not topic:
            return False
        lower = topic.lower()
        if lower in self.GENERIC_PROJECT_DIRS or topic == "共同主题" or topic in self.SHORT_PROJECT_BLOCKLIST or re.fullmatch(r"\d{4}[-_.年]?\d{1,2}[-_.月]?\d{0,2}", lower):
            return False
        if re.fullmatch(r"(wechat|weixin|qq|tim|img|dsc|pxl|copy|screenrecording|screen recording).*", lower):
            return False
        if re.fullmatch(r"[a-f0-9]{12,}.*", lower) or re.fullmatch(r"\d+([_-]\d+)?", lower):
            return False
        if self._has_any(lower, ("截图", "微信图片", "qq截图", "image", "video", "下载", "源素材", "背景", "未标题", "filelist", "预览视频", "仅自己可见", "配音demo")):
            return False
        content_keywords = (
            "练习册", "课程", "课堂", "课件", "教材", "试题", "习题", "高考", "期中", "期末",
            "科普", "工程", "计算机", "数据库", "数据集", "生态", "文明", "读书", "好书", "营销", "产品介绍",
            "宣传片", "短视频", "视频号", "栏目", "专题", "片头", "全息", "科技", "朗诵", "总结", "vlog",
        )
        if self._has_any(topic, content_keywords):
            return True
        return False

    def _is_project_like_folder(self, path: Path) -> bool:
        lower = path.name.lower()
        if self._folder_has_any(path, {"package.json", "pyproject.toml", ".git", "src", "src-tauri"}):
            return True
        return self._has_any(lower, ("tool", "generator", "converter", "源码", "工程", "工具"))

    def _project_role(self, path: Path, project: str) -> str:
        name = path.name
        lower = name.lower()
        ext = path.suffix.lower()
        if path.is_dir():
            if self._folder_has_any(path, {"package.json", "pyproject.toml", ".git", "src", "src-tauri"}) or self._has_any(lower, ("generator", "tool", "源码", "source")):
                return "01_源码工程"
            if re.match(r"^(dist|release|publish|output|out)[_-]?", lower) or self._folder_has_ext(path, self.INSTALLER_EXTS | {".exe", ".msi", ".zip"}):
                return "04_发布包与安装包"
            if self._folder_mostly_ext(path, self.IMAGE_EXTS | self.VIDEO_EXTS):
                return "03_图片视频素材"
            return "05_项目资料夹"
        if ext in self.CODE_EXTS:
            return "01_脚本与源码"
        if ext in self.PROJECT_BUNDLE_EXTS:
            return "01_剪辑工程文件"
        if ext in self.INSTALLER_EXTS or ext in {".apk", ".ipa"}:
            return "04_发布包与安装包"
        if ext in self.ARCHIVE_EXTS and self._has_any(lower, ("win", "release", "安装", "发布", "dist")):
            return "04_发布包与安装包"
        if ext in self.VIDEO_EXTS:
            return "04_视频成片与素材"
        if ext in self.IMAGE_EXTS or ext in self.DESIGN_EXTS:
            return "03_图片素材与配图"
        if ext in self.AUDIO_EXTS:
            return "05_音频素材与录音"
        if ext in self.DOC_EXTS or ext in self.EBOOK_EXTS:
            if "口播稿" in project or "口播" in lower:
                if self._has_any(lower, ("终稿", "最终", "定稿")):
                    return "02_文稿成品/终稿"
                if self._has_any(lower, ("精简版", "简版")):
                    return "02_文稿成品/精简版"
                return "02_文稿成品/分篇与合集"
            if self._has_any(lower, ("说明", "readme", "使用说明", "教程")):
                return "05_说明文档"
            if ext in {".pdf", ".doc", ".docx", ".ppt", ".pptx"}:
                return "02_文稿脚本与资料"
            return "02_文稿脚本与资料"
        if ext in self.DATA_EXTS:
            return "06_数据表格"
        return "05_项目资料"

    def _folder_mostly_ext(self, path: Path, exts: set[str]) -> bool:
        total = 0
        hits = 0
        try:
            for child in path.iterdir():
                if not child.is_file():
                    continue
                total += 1
                if child.suffix.lower() in exts:
                    hits += 1
                if total >= 30:
                    break
        except OSError:
            return False
        return total > 0 and hits / total >= 0.7

    def _classify_media_deep(self, path: Path, modified_month: str) -> tuple[str, int, str] | None:
        ext = path.suffix.lower()
        lower = path.name.lower()
        context = " ".join([lower, *(part.lower() for part in path.parts[-4:-1])])
        if ext in self.IMAGE_EXTS:
            ai_source = self._detect_ai_image_source(path, context)
            if ai_source:
                return self._result(f"02_图片视频与AI素材/AI生成素材/{ai_source}/{modified_month}", 95, "读取图片元数据或命名特征，识别为 AI 平台/模型生成图片")
            camera = self._detect_image_camera(path)
            if camera:
                return self._result(f"02_图片视频与AI素材/实拍照片/{camera}/{modified_month}", 91, "读取 EXIF 相机品牌/型号，按拍摄设备归档")
            editor = self._detect_image_editor(path)
            if editor:
                return self._result(f"02_图片视频与AI素材/修图导出/{editor}/{modified_month}", 84, "读取图片软件元数据，识别为修图或设计软件导出")
            platform = self._detect_media_platform(context)
            if platform:
                return self._result(f"02_图片视频与AI素材/平台接收与下载图片/{platform}/{modified_month}", 82, "命名或路径显示为平台接收、下载或导出的图片")
        if ext in self.VIDEO_EXTS:
            platform = self._detect_media_platform(context)
            if platform == "OBS录屏":
                return self._result(f"11_音频视频资料/录屏与教程视频/{platform}/{modified_month}", 88, "命名或路径显示为录屏软件导出")
            if platform == "剪映导出":
                return self._result(f"11_音频视频资料/剪辑导出视频/{platform}/{modified_month}", 88, "命名或路径显示为剪辑软件导出视频")
            if platform:
                return self._result(f"11_音频视频资料/平台下载视频/{platform}/{modified_month}", 84, "命名或路径显示为平台下载或接收的视频")
            device = self._detect_video_device_name(lower)
            if device:
                return self._result(f"11_音频视频资料/相机手机视频/{device}/{modified_month}", 82, "命名模式像相机、运动相机、无人机或手机拍摄视频")
        if ext in self.AUDIO_EXTS:
            platform = self._detect_media_platform(context)
            if platform:
                return self._result(f"11_音频视频资料/平台接收音频/{platform}/{modified_month}", 82, "命名或路径显示为平台接收、下载或导出的音频")
            if self._has_any(context, ("voice", "record", "recorder", "录音", "语音", "memo", "meeting", "会议")):
                return self._result(f"11_音频视频资料/录音与语音备忘/{modified_month}", 84, "命名显示为录音、语音备忘或会议音频")
            if self._has_any(context, ("bgm", "sound", "sfx", "音效", "配乐", "素材", "loop")):
                return self._result(f"11_音频视频资料/音乐音效素材/{modified_month}", 84, "命名显示为配乐、音效或音频素材")
        return None

    def _code_project_topic(self, name: str, theme: str | None = None) -> str | None:
        lower = name.lower()
        checks = (
            ("视频片头片尾工具", ("片头", "片尾", "视频片头", "视频片尾")),
            ("批量水印工具", ("水印", "watermark")),
            ("麻将规则与番种图解", ("麻将", "番种", "番型", "图解")),
            ("图书3D生成工具", ("book-3d", "3d-generator", "书籍3d", "图书3d")),
        )
        for topic, keywords in checks:
            if self._has_any(lower, keywords):
                return topic
        if theme:
            cleaned = self._clean_topic(theme)
            if cleaned and cleaned not in {"共同主题", "生成", "最终", "版本"}:
                return cleaned
        return None

    def _classify_office_deep(self, path: Path, modified_month: str, theme: str | None = None) -> tuple[str, int, str] | None:
        ext = path.suffix.lower()
        lower = " ".join([path.name.lower(), *(part.lower() for part in path.parts[-4:-1])])
        is_sheet = ext in {".xlsx", ".xls", ".numbers", ".csv", ".tsv"}
        is_slide = ext in {".ppt", ".pptx", ".key"}
        is_doc = ext in {".doc", ".docx", ".pdf", ".txt", ".md", ".rtf", ".pages"}
        if not (is_sheet or is_slide or is_doc):
            return None
        if self._has_any(lower, ("合同", "协议", "授权", "盖章", "签署", "签字", "保密", "nda")):
            return self._result("05_重要资料/合同协议与盖章文件", 92, "办公文件命中合同、协议、授权、签署或盖章线索")
        if self._has_any(lower, ("发票", "报销", "账单", "收据", "付款", "回款", "工资", "税", "个税", "报价", "预算", "采购")):
            return self._result("05_重要资料/财务票据与报销", 91, "办公文件命中发票、报销、账单、工资、税务或报价预算线索")
        if self._has_any(lower, ("简历", "身份证", "护照", "证书", "证明", "offer", "录取", "档案", "社保", "医保")):
            return self._result("05_重要资料/人员证件与证明材料", 91, "办公文件命中人员、证件、证明、简历或档案线索")
        if self._has_any(lower, ("会议", "纪要", "备忘", "周会", "月会", "复盘", "日报", "周报", "月报")):
            return self._result(f"06_办公文档与学习/会议纪要与工作汇报/{modified_month}", 88, "办公文件命中会议、纪要、复盘或周期汇报线索")
        if self._has_any(lower, ("方案", "计划", "规划", "需求", "prd", "提案", "项目书", "立项", "roadmap", "排期")):
            return self._result("06_办公文档与学习/方案计划与项目资料", 88, "办公文件命中方案、计划、需求、立项或排期线索")
        if self._has_any(lower, ("客户", "销售", "线索", "crm", "渠道", "分销", "订单", "发货", "库存", "入库", "出库", "物流")):
            return self._result("10_数据表格与备份/客户销售订单与库存", 88, "办公文件命中客户、销售、订单、库存或物流线索")
        if self._has_any(lower, ("报表", "统计", "台账", "清单", "明细", "汇总", "导出", "数据", "分析", "看板")):
            return self._result(f"10_数据表格与备份/报表台账与数据分析/{modified_month}", 87, "办公文件命中报表、统计、台账、清单、导出或分析线索")
        if self._has_any(lower, ("课件", "课程", "教材", "讲义", "教案", "论文", "作业", "题库", "培训", "教程")):
            return self._result("06_办公文档与学习/课件培训与学习资料", 87, "办公文件命中课件、课程、教材、培训或论文作业线索")
        if self._has_any(lower, ("宣传", "活动", "发布会", "路演", "招商", "营销", "运营", "海报", "直播", "促销")):
            return self._result("01_主题项目资料/宣传活动与运营物料", 86, "办公文件命中宣传、活动、营销、运营或发布会线索")
        if self._has_any(lower, self.PUBLISHING_TOPICS):
            return self._result("01_出版项目资料/书稿版权与上架资料", 86, "办公文件命中出版、书影、版权、上架或图书项目线索")
        if is_slide:
            return self._result(f"06_办公文档与学习/PPT汇报与演示/{modified_month}", 82, "演示文稿未命中特定业务，按汇报演示归档")
        if is_sheet:
            return self._result(f"10_数据表格与备份/表格清单与导出/{modified_month}", 82, "表格文件未命中特定业务，按表格清单归档")
        if theme:
            return self._result(f"01_主题项目资料/{self._clean_topic(theme)}", 84, f"同批办公文件反复出现“{theme}”，按共同主题聚合")
        return None

    def _detect_media_platform(self, text: str) -> str | None:
        for name, pattern in self.MEDIA_PLATFORM_PATTERNS:
            if pattern.search(text):
                return name
        return None

    def _detect_ai_image_source(self, path: Path, context: str) -> str | None:
        for source_name, pattern in self.AI_SOURCE_PATTERNS:
            if pattern.search(context):
                return source_name
        metadata = self._image_metadata_text(path)
        checks = (
            ("ComfyUI生成素材", r"comfyui|workflow|ksampler|nodes"),
            ("StableDiffusion生成素材", r"stable.?diffusion|automatic1111|negative prompt|sampler|cfg scale|sdxl|checkpoint|lora"),
            ("NovelAI生成素材", r"novelai|nai metadata"),
            ("DALL-E生成素材", r"dall[·._ -]?e|openai image|gpt-image"),
            ("Midjourney生成素材", r"midjourney|mj version|--ar|--stylize"),
            ("AdobeFirefly生成素材", r"firefly|adobe generative"),
            ("Leonardo生成素材", r"leonardo\\.ai|leonardo"),
            ("Gemini生成素材", r"gemini|google ai"),
        )
        for source, pattern in checks:
            if re.search(pattern, metadata, re.I):
                return source
        return None

    def _detect_image_camera(self, path: Path) -> str | None:
        exif = self._read_image_exif(path)
        make = self._clean_metadata_value(exif.get("Make", ""))
        model = self._clean_metadata_value(exif.get("Model", ""))
        camera = re.sub(r"\s+", " ", " ".join(part for part in (make, model) if part)).strip()
        return self._clean_topic(camera) if camera else None

    def _detect_image_editor(self, path: Path) -> str | None:
        exif = self._read_image_exif(path)
        metadata = " ".join([self._clean_metadata_value(exif.get("Software", "")), self._image_metadata_text(path)])
        for name, pattern in (("Photoshop", r"photoshop"), ("Lightroom", r"lightroom"), ("CaptureOne", r"capture one"), ("Canva", r"canva"), ("Figma", r"figma"), ("Procreate", r"procreate")):
            if re.search(pattern, metadata, re.I):
                return name
        return None

    def _image_metadata_text(self, path: Path) -> str:
        if Image is None:
            return ""
        try:
            with Image.open(path) as image:
                pieces = [f"{key}:{value}" for key, value in image.info.items() if isinstance(value, (str, bytes, int, float))]
                exif = image.getexif()
                if exif:
                    tags = ExifTags.TAGS if ExifTags else {}
                    for tag_id, value in exif.items():
                        tag = tags.get(tag_id, str(tag_id))
                        if tag in {"Software", "Make", "Model", "ImageDescription"}:
                            pieces.append(f"{tag}:{value}")
                return " ".join(str(piece) for piece in pieces)[:6000]
        except Exception:
            return ""

    def _read_image_exif(self, path: Path) -> dict[str, str]:
        if Image is None:
            return {}
        try:
            with Image.open(path) as image:
                exif = image.getexif()
                if not exif:
                    return {}
                tags = ExifTags.TAGS if ExifTags else {}
                return {str(tags.get(tag_id, tag_id)): str(value) for tag_id, value in exif.items()}
        except Exception:
            return {}

    @staticmethod
    def _clean_metadata_value(value: str) -> str:
        value = re.sub(r"[\x00-\x1f]+", " ", str(value)).strip()
        return re.sub(r"\s+", " ", value)

    @staticmethod
    def _detect_video_device_name(lower_name: str) -> str | None:
        if re.search(r"^(gopr|gh|gx)\d+|gopro", lower_name):
            return "GoPro运动相机"
        if re.search(r"^dji|dji_", lower_name):
            return "DJI无人机或运动相机"
        if re.search(r"^(mvi_|c\d{3,}|dsc_|mov_)", lower_name):
            return "相机拍摄视频"
        if re.search(r"^(vid_|pxl_|img_\d{8})", lower_name):
            return "手机拍摄视频"
        return None

    @classmethod
    def topic_tokens(cls, name: str) -> set[str]:
        stem = Path(name).stem.lower()
        stem = cls.DATE_TOKEN_REGEX.sub(" ", stem)
        tokens = set(cls.TOKEN_REGEX.findall(stem))
        return {
            token
            for token in tokens
            if token not in cls.STOP_WORDS
            and not token.isdigit()
            and not any(token.startswith(stop) for stop in ("新建", "未命名"))
            and ("\u4e00" <= token[0] <= "\u9fff" or len(token) >= 6)
        }

    @staticmethod
    def _is_person_profile_pdf(name: str, ext: str) -> bool:
        if ext != ".pdf":
            return False
        stem = Path(name).stem
        stem = re.sub(r"[\s_-]*\(\d+\)$", "", stem).strip()
        if any(token in stem for token in ("版权", "版权页", "扉页", "文前", "内文", "目录", "封面", "腰封", "书影")):
            return False
        if re.fullmatch(r"[\u4e00-\u9fff]{2,4}", stem):
            return True
        if re.fullmatch(r"[\u4e00-\u9fff]{2,4}[-_]\d+", stem):
            return True
        return False

    @classmethod
    def _clean_topic(cls, topic: str) -> str:
        topic = re.sub(r'[<>:"/\\|?*]+', "_", topic).strip(" ._")
        return topic[:24] if topic else "共同主题"

    @staticmethod
    def _result(category: str, confidence: int, reason: str) -> tuple[str, int, str]:
        return category, confidence, reason

    @staticmethod
    def _has_any(text: str, keywords: tuple[str, ...]) -> bool:
        for keyword in keywords:
            key = keyword.lower()
            if not key:
                continue
            if key.isascii() and key.replace("_", "").isalnum() and len(key) <= 3:
                if re.search(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", text):
                    return True
                continue
            if key in text:
                return True
        return False

    def _is_dev_build_artifact(self, path: Path) -> bool:
        lower_name = path.name.lower()
        lower_parts = {part.lower() for part in path.parts}
        build_dirs = {"__pycache__", "build", "dist", ".vs", "bin", "obj", "_internal", "platforms", "tcl", "tk", "encoding", "msgs"}
        structural_build_dirs = {"__pycache__", ".vs", "obj", "_internal", "tcl", "tk", "encoding", "msgs", "venv", "build_venv", ".venv", "site-packages", "dist-info"}
        if lower_parts & structural_build_dirs:
            return True
        if lower_name.endswith(".csproj.user"):
            return True
        if lower_name in {".suo", ".cache"}:
            return True
        if path.suffix.lower() in self.DEV_ARTIFACT_EXTS and (lower_parts & build_dirs):
            return True
        if lower_parts & build_dirs:
            if path.suffix.lower() in self.CODE_EXTS | self.DEV_ARTIFACT_EXTS | self.INSTALLER_EXTS | self.ARCHIVE_EXTS | {".manifest", ".res"}:
                return True
        if re.match(r"^(analysis|exe|pkg|pyz)-\d+\.toc$", lower_name):
            return True
        if lower_name.startswith(("pyimod", "pyi_")) or lower_name in {"base_library.zip", "warn.txt", "xref.html"}:
            return True
        return False

    @staticmethod
    def _has_post_context(path: Path) -> bool:
        context = "/".join(part.lower() for part in path.parts[-5:-1])
        tokens = (
            "ae模板",
            "pr模板",
            "premiere",
            "adobe premiere pro",
            "after effects",
            "剪辑模板",
            "片头",
            "工程素材",
            "渲染序列",
            "素材)",
            "(footage)",
            "footage",
            "c4d_out",
            "audio previews",
            "peak files",
            ".prv",
        )
        return any(token in context for token in tokens)

    def _is_post_project_dir(self, path: Path) -> bool:
        if not path.is_dir():
            return False
        lower = path.name.lower()
        if self._has_any(lower, ("ae模板", "pr模板", "premiere", "after effects", "剪辑工程", "片头工程")):
            return True
        try:
            direct_files = [child for child in path.iterdir() if child.is_file()]
        except OSError:
            return False
        if any(child.suffix.lower() in self.PROJECT_BUNDLE_EXTS for child in direct_files):
            return True
        technical_dirs = {"(footage)", "footage", "素材", "(素材)", "adobe premiere pro audio previews", "adobe premiere pro auto-save"}
        try:
            direct_dirs = {child.name.lower() for child in path.iterdir() if child.is_dir()}
        except OSError:
            direct_dirs = set()
        if direct_dirs & technical_dirs:
            try:
                return any(child.is_file() and child.suffix.lower() in self.PROJECT_BUNDLE_EXTS for child in path.rglob("*"))
            except OSError:
                return False
        return False

    def _is_post_sidecar_dir(self, path: Path) -> bool:
        if not path.is_dir():
            return False
        sidecar_names = {"(footage)", "footage", "(素材)", "素材", "images", "assets", "links", "source", "源文件"}
        if path.name.lower() not in sidecar_names:
            return False
        try:
            return any(sibling.is_file() and sibling.suffix.lower() in self.PROJECT_BUNDLE_EXTS for sibling in path.parent.iterdir())
        except OSError:
            return False

    @staticmethod
    def _folder_has_any(path: Path, names: set[str]) -> bool:
        try:
            existing = {child.name.lower() for child in path.iterdir()}
        except OSError:
            return False
        return any(name.lower() in existing for name in names)

    @staticmethod
    def _folder_has_ext(path: Path, exts: set[str]) -> bool:
        try:
            for child in path.iterdir():
                if child.is_file() and child.suffix.lower() in exts:
                    return True
        except OSError:
            return False
        return False


class Organizer:
    def __init__(self, rules_data: dict | None = None) -> None:
        self.classifier = SmartClassifier(rules_data=rules_data)

    def build_plan(
        self,
        root: Path,
        mode: str,
        cutoff: datetime | None,
        include_folders: bool,
    ) -> tuple[Path, list[PlanItem]]:
        archive_root = self._choose_archive_root(root, mode, cutoff)
        items = []
        candidates = [
            item
            for item in sorted(root.iterdir(), key=lambda p: (p.stat().st_mtime, p.name.lower()))
            if not self._should_skip(item, archive_root, include_folders)
        ]
        theme_by_name = self._theme_map(candidates)
        for item in candidates:
            modified_at = datetime.fromtimestamp(item.stat().st_mtime)
            if cutoff and modified_at >= cutoff:
                continue
            category, confidence, reason = self.classifier.classify_detailed(item, theme_by_name.get(item.name))
            if mode == "按月份归档":
                category = f"{modified_at.strftime('%Y-%m')}/{category}"
            dest_dir = archive_root / Path(category)
            dest = self._unique_destination(dest_dir, item.name)
            items.append(
                PlanItem(
                    source=item,
                    destination=dest,
                    category=category,
                    confidence=confidence,
                    reason=reason,
                    size_bytes=self._size_bytes(item),
                    modified_at=modified_at,
                    is_dir=item.is_dir(),
                )
            )
        return archive_root, items

    def _theme_map(self, items: list[Path]) -> dict[str, str]:
        counts: dict[str, int] = {}
        item_tokens: dict[str, set[str]] = {}
        for item in items:
            tokens = self.classifier.topic_tokens(item.name)
            item_tokens[item.name] = tokens
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
        recurring = {
            token
            for token, count in counts.items()
            if token not in self.classifier.SHORT_PROJECT_BLOCKLIST
            and token.lower() not in self.classifier.GENERIC_PROJECT_DIRS
            and (
                count >= 3
                or (count >= 2 and (len(token) >= 5 or ("\u4e00" <= token[0] <= "\u9fff" and len(token) >= 4)))
                or (count >= 4 and "\u4e00" <= token[0] <= "\u9fff" and len(token) >= 2)
            )
        }
        result: dict[str, str] = {}
        for name, tokens in item_tokens.items():
            matched = sorted(tokens & recurring, key=lambda token: (-counts[token], -len(token), token))
            if matched:
                theme = self.classifier._normalize_project_topic(matched[0])
                if 2 <= len(theme) <= 4 and "\u4e00" <= theme[0] <= "\u9fff" and theme not in self.classifier.SHORT_PROJECT_BLOCKLIST:
                    theme = f"{theme}内容项目"
                result[name] = theme
        return result

    def execute_plan(self, archive_root: Path, plan: list[PlanItem], cutoff: datetime | None = None) -> MoveResult:
        archive_root.mkdir(parents=True, exist_ok=True)
        self._write_marker(archive_root)
        records = []
        failures: list[tuple[str, str]] = []
        for item in plan:
            try:
                item.destination.parent.mkdir(parents=True, exist_ok=True)
                final_destination = self._unique_destination(item.destination.parent, item.destination.name)
                shutil.move(str(item.source), str(final_destination))
                records.append(
                    {
                        "原路径": str(item.source),
                        "新路径": str(final_destination),
                        "分类": item.category,
                        "可信度": item.confidence,
                        "判断依据": item.reason,
                        "类型": "文件夹" if item.is_dir else item.source.suffix.lower(),
                        "大小MB": round(item.size_bytes / 1024 / 1024, 2),
                        "修改时间": item.modified_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "整理时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except Exception as exc:
                failures.append((str(item.source), str(exc)))
        final_archive = self._rename_archive_with_cutoff(archive_root, cutoff)
        if final_archive != archive_root:
            for record in records:
                moved_path = Path(record["新路径"])
                try:
                    record["新路径"] = str(final_archive / moved_path.relative_to(archive_root))
                except ValueError:
                    record["新路径"] = str(moved_path)
            archive_root = final_archive
            self._write_marker(archive_root)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = archive_root / f"整理清单_{stamp}.csv"
        with log_path.open("w", newline="", encoding="utf-8-sig") as f:
            fields = list(records[0].keys()) if records else ["原路径", "新路径", "分类", "可信度", "判断依据", "类型", "大小MB", "修改时间", "整理时间"]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)
        rollback_path = archive_root / f"恢复记录_{stamp}.json"
        rollback_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        if failures:
            failure_path = archive_root / f"失败记录_{stamp}.csv"
            with failure_path.open("w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=["路径", "失败原因"])
                writer.writeheader()
                writer.writerows({"路径": path, "失败原因": reason} for path, reason in failures)
        self._write_readme(archive_root, plan)
        return MoveResult(log_path, rollback_path, len(records), len(failures), failures, final_archive)

    def archive_rule_state(self, archive_root: Path) -> dict:
        marker = self._read_marker(archive_root) or {}
        archive_hash = str(marker.get("rules_hash", ""))
        snapshot = marker.get("rules_snapshot")
        return {
            "has_marker": bool(marker),
            "archive_hash": archive_hash,
            "current_hash": self.classifier.rules_hash,
            "archive_version": str(marker.get("rules_version", "")),
            "current_version": self.classifier.rules_version,
            "snapshot": snapshot if isinstance(snapshot, dict) else None,
            "changed": bool(marker) and archive_hash != self.classifier.rules_hash,
        }

    def reclassify_archive(self, archive_root: Path) -> MoveResult:
        archive_root.mkdir(parents=True, exist_ok=True)
        self._write_marker(archive_root)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        records = []
        failures: list[tuple[str, str]] = []
        protected_dirs = self._protected_project_dirs(archive_root)
        moved_protected_dirs: set[Path] = set()
        for project_dir in protected_dirs:
            try:
                if not project_dir.exists() or not project_dir.is_dir():
                    continue
                category, confidence, reason = self.classifier.classify_detailed(project_dir)
                dest_dir = archive_root / Path(category)
                if project_dir.parent == dest_dir:
                    continue
                dest_dir.mkdir(parents=True, exist_ok=True)
                final_destination = self._unique_destination(dest_dir, project_dir.name)
                size_bytes = self._size_bytes(project_dir)
                modified_at = datetime.fromtimestamp(project_dir.stat().st_mtime)
                shutil.move(str(project_dir), str(final_destination))
                moved_protected_dirs.add(final_destination)
                records.append(
                    {
                        "source_path": str(project_dir),
                        "new_path": str(final_destination),
                        "category": category,
                        "confidence": confidence,
                        "reason": reason + "；整包移动，未拆分内部素材",
                        "type": "project_dir",
                        "size_mb": round(size_bytes / 1024 / 1024, 2),
                        "modified_at": modified_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "organized_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except Exception as exc:
                failures.append((str(project_dir), str(exc)))
        protected_dirs = {path for path in protected_dirs if path.exists()} | moved_protected_dirs
        candidates = [
            item
            for item in archive_root.rglob("*")
            if item.is_file() and not self._is_archive_meta_file(item) and not self._is_inside_any(item, protected_dirs)
        ]
        for item in candidates:
            try:
                category, confidence, reason = self.classifier.classify_detailed(item)
                dest_dir = archive_root / Path(category)
                if item.parent == dest_dir:
                    continue
                dest_dir.mkdir(parents=True, exist_ok=True)
                final_destination = self._unique_destination(dest_dir, item.name)
                size_bytes = item.stat().st_size
                modified_at = datetime.fromtimestamp(item.stat().st_mtime)
                shutil.move(str(item), str(final_destination))
                records.append(
                    {
                        "source_path": str(item),
                        "new_path": str(final_destination),
                        "category": category,
                        "confidence": confidence,
                        "reason": reason,
                        "type": item.suffix.lower(),
                        "size_mb": round(size_bytes / 1024 / 1024, 2),
                        "modified_at": modified_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "organized_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except Exception as exc:
                failures.append((str(item), str(exc)))
        self._cleanup_empty_dirs(archive_root)
        log_path = archive_root / f"\u89c4\u5219\u91cd\u6574\u6e05\u5355_{stamp}.csv"
        with log_path.open("w", newline="", encoding="utf-8-sig") as f:
            fields = list(records[0].keys()) if records else ["source_path", "new_path", "category", "confidence", "reason", "type", "size_mb", "modified_at", "organized_at"]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(records)
        rollback_path = archive_root / f"\u6062\u590d\u8bb0\u5f55_\u89c4\u5219\u91cd\u6574_{stamp}.json"
        rollback_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        if failures:
            failure_path = archive_root / f"\u5931\u8d25\u8bb0\u5f55_\u89c4\u5219\u91cd\u6574_{stamp}.csv"
            with failure_path.open("w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=["path", "reason"])
                writer.writeheader()
                writer.writerows({"path": path, "reason": reason} for path, reason in failures)
        self._write_marker(archive_root)
        return MoveResult(log_path, rollback_path, len(records), len(failures), failures, archive_root)

    def undo_latest(self, root: Path, archive_root: Path | None = None) -> tuple[int, Path | None]:
        if archive_root:
            logs = [
                RecoveryLog(path=log, archive_root=archive_root, item_count=self._recovery_count(log), modified_at=datetime.fromtimestamp(log.stat().st_mtime))
                for log in archive_root.glob("恢复记录_*.json")
                if "_已恢复" not in log.stem
            ]
            logs.sort(key=lambda item: item.modified_at, reverse=True)
        else:
            logs = self.list_recovery_logs(root)
        if not logs:
            return 0, None
        latest = logs[0].path
        return self.restore_from_log(latest)

    def list_recovery_logs(self, root: Path) -> list[RecoveryLog]:
        logs: list[RecoveryLog] = []
        for log in root.rglob("恢复记录_*.json"):
            if "_已恢复" in log.stem:
                continue
            try:
                item_count = self._recovery_count(log)
                modified_at = datetime.fromtimestamp(log.stat().st_mtime)
            except (OSError, json.JSONDecodeError):
                continue
            logs.append(RecoveryLog(log, log.parent, item_count, modified_at))
        logs.sort(key=lambda item: item.modified_at, reverse=True)
        return logs

    def restore_from_log(self, log_path: Path) -> tuple[int, Path | None]:
        if not log_path.exists():
            return 0, None
        records = json.loads(log_path.read_text(encoding="utf-8"))
        restored = 0
        for record in reversed(records):
            src = Path(record.get("新路径") or record.get("new_path"))
            dst = Path(record.get("原路径") or record.get("source_path"))
            if not src.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            final_dst = self._unique_destination(dst.parent, dst.name) if dst.exists() else dst
            shutil.move(str(src), str(final_dst))
            restored += 1
        done_log = log_path.with_name(log_path.stem + "_已恢复.json")
        log_path.rename(done_log)
        return restored, done_log

    @staticmethod
    def _recovery_count(log_path: Path) -> int:
        records = json.loads(log_path.read_text(encoding="utf-8"))
        return len(records) if isinstance(records, list) else 0

    def _choose_archive_root(self, root: Path, mode: str, cutoff: datetime | None) -> Path:
        if mode == "续整理到已有归档":
            existing = self._find_existing_archive(root)
            if existing:
                return existing
            return root / f"资料归档_至{self._archive_cutoff_stamp(cutoff)}"
        if mode == "新建本次归档":
            return root / f"本次归档_{datetime.now().strftime('%Y%m%d_%H%M')}"
        return root / "按月份归档"

    def _find_existing_archive(self, root: Path) -> Path | None:
        candidates = []
        for item in root.iterdir():
            if not item.is_dir():
                continue
            has_marker = (item / ARCHIVE_MARKER).exists()
            archive_like = "归档" in item.name or "整理" in item.name
            has_old_list = any(item.glob("整理清单*.csv"))
            if has_marker or (archive_like and has_old_list):
                candidates.append(item)
        if not candidates:
            return None
        preferred = [
            item
            for item in candidates
            if "资料归档" in item.name or re.search(r"至\d{8}", item.name) or "持续整理" in item.name
        ]
        pool = preferred or candidates
        return max(pool, key=lambda p: p.stat().st_mtime)

    def _should_skip(self, item: Path, archive_root: Path, include_folders: bool) -> bool:
        if item == archive_root:
            return True
        if item.name.lower() in SmartClassifier.SKIP_NAMES:
            return True
        if item.name.startswith("~$"):
            return True
        if item.name.startswith("."):
            return True
        if item.is_file() and self._is_archive_meta_file(item):
            return True
        if item.is_file() and self._is_workspace_root_marker_file(item):
            return True
        if item.is_dir() and not include_folders:
            return True
        if item.is_dir() and self._is_empty_dir(item):
            return True
        if item.is_dir() and self._is_archive_dir(item):
            return True
        if item.is_dir() and self._is_existing_category_dir(item):
            return True
        if item.is_dir() and self._is_workspace_internal_dir(item):
            return True
        return False

    @staticmethod
    def _is_empty_dir(path: Path) -> bool:
        try:
            next(path.iterdir())
            return False
        except StopIteration:
            return True
        except OSError:
            return False

    @staticmethod
    def _is_archive_dir(path: Path) -> bool:
        return (
            (path / ARCHIVE_MARKER).exists()
            or "归档" in path.name
            or path.name in {"按月份归档", "资料归档_持续整理"}
        )

    @staticmethod
    def _is_existing_category_dir(path: Path) -> bool:
        if not path.is_dir():
            return False
        name = path.name
        if re.match(r"^\d{2}[_-]", name):
            return True
        known_roots = {
            "图片", "视频", "音频", "文档", "资料", "素材", "源码", "脚本", "安装包",
            "办公文档", "项目资料", "设计资产", "软件工具", "备份归档", "临时与测试",
        }
        if name not in known_roots:
            return False
        parent = path.parent
        try:
            archive_marked = (parent / ARCHIVE_MARKER).exists() or any(parent.glob("整理清单*.csv"))
        except OSError:
            archive_marked = False
        return archive_marked or "归档" in parent.name or parent.name in {"按月份归档", "资料归档_持续整理"}

    @staticmethod
    def _is_workspace_internal_dir(path: Path) -> bool:
        if not path.is_dir():
            return False
        name = path.name.lower()
        if name in {"node_modules", ".venv", "venv", "__pycache__", ".git", ".idea", ".vscode"}:
            return True
        if name in {"build", "dist", "out", "target", ".next"}:
            parent_names = {child.name.lower() for child in path.parent.iterdir()}
            project_markers = {"package.json", "pyproject.toml", "cargo.toml", ".git", "requirements.txt"}
            return bool(parent_names & project_markers)
        return False

    @staticmethod
    def _is_workspace_root_marker_file(path: Path) -> bool:
        name = path.name.lower()
        marker_files = {
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "pyproject.toml", "requirements.txt", "cargo.toml", "go.mod",
        }
        if name not in marker_files:
            return False
        try:
            sibling_names = {child.name.lower() for child in path.parent.iterdir()}
        except OSError:
            return False
        workspace_dirs = {"node_modules", "src", ".git", ".venv", "venv"}
        return bool(sibling_names & workspace_dirs)

    @staticmethod
    def _is_archive_meta_file(path: Path) -> bool:
        if path.name == ARCHIVE_MARKER:
            return True
        meta_tokens = (
            "\u6574\u7406\u6e05\u5355",
            "\u89c4\u5219\u91cd\u6574\u6e05\u5355",
            "\u6062\u590d\u8bb0\u5f55",
            "\u5931\u8d25\u8bb0\u5f55",
            "\u5f52\u6863\u8bf4\u660e",
            "\u6574\u7406\u8bf4\u660e",
        )
        return any(token in path.name for token in meta_tokens)

    def _protected_project_dirs(self, archive_root: Path) -> set[Path]:
        raw_roots: set[Path] = set()
        raw_roots.update(self._protected_workspace_dirs(archive_root))
        project_exts = self.classifier.PROJECT_BUNDLE_EXTS
        for project_file in archive_root.rglob("*"):
            if not project_file.is_file() or self._is_archive_meta_file(project_file):
                continue
            if project_file.suffix.lower() not in project_exts:
                continue
            root = self._project_root_for_file(project_file, archive_root)
            if root != archive_root:
                raw_roots.add(root)
            raw_roots.update(self._post_sidecar_siblings(project_file))
        protected: set[Path] = set()
        for root in sorted(raw_roots, key=lambda path: len(path.parts)):
            if not self._is_inside_any(root, protected):
                protected.add(root)
        return protected

    def _protected_workspace_dirs(self, archive_root: Path) -> set[Path]:
        markers = {"package.json", "pyproject.toml", "cargo.toml", "go.mod", ".git"}
        ignored_parts = {"node_modules", "target", "build", "dist", ".git", "__pycache__", ".venv", "venv"}
        roots: set[Path] = set()
        try:
            for item in archive_root.rglob("*"):
                if item.name not in markers:
                    if item.name.lower() in ignored_parts and item.is_dir():
                        continue
                    continue
                if any(part.lower() in ignored_parts for part in item.relative_to(archive_root).parts[:-1]):
                    continue
                root = item.parent
                if root != archive_root:
                    roots.add(root)
        except OSError:
            return roots
        return roots

    @staticmethod
    def _project_root_for_file(project_file: Path, archive_root: Path) -> Path:
        root = project_file.parent
        technical_names = {
            "adobe premiere pro auto-save",
            "adobe premiere pro audio previews",
            "peak files",
            "(footage)",
            "footage",
            "(素材)",
            "素材",
        }
        while root.parent != archive_root and root.name.lower() in technical_names:
            root = root.parent
        if root.name.lower() == "peak files" and root.parent.parent != archive_root:
            root = root.parent.parent
        return root

    @staticmethod
    def _post_sidecar_siblings(project_file: Path) -> set[Path]:
        sidecar_names = {"(footage)", "footage", "(素材)", "素材", "images", "assets", "links", "source", "源文件"}
        result: set[Path] = set()
        try:
            siblings = list(project_file.parent.iterdir())
        except OSError:
            return result
        for sibling in siblings:
            if sibling.is_dir() and sibling.name.lower() in sidecar_names:
                result.add(sibling)
        return result

    @staticmethod
    def _is_inside_any(path: Path, roots: set[Path]) -> bool:
        for root in roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _cleanup_empty_dirs(root: Path) -> None:
        folders = [item for item in root.rglob("*") if item.is_dir()]
        folders.sort(key=lambda path: len(path.parts), reverse=True)
        for folder in folders:
            try:
                folder.rmdir()
            except OSError:
                continue

    @staticmethod
    def _unique_destination(dest_dir: Path, name: str) -> Path:
        dest = dest_dir / name
        if not dest.exists():
            return dest
        stem = Path(name).stem
        suffix = Path(name).suffix
        i = 1
        while True:
            candidate = dest_dir / f"{stem}_重复{i}{suffix}"
            if not candidate.exists():
                return candidate
            i += 1

    @staticmethod
    def _size_bytes(path: Path) -> int:
        if path.is_file():
            return path.stat().st_size
        total = 0
        stack = [path]
        checked = 0
        max_entries = 2000
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                            checked += 1
                            if checked >= max_entries:
                                return total
                        except OSError:
                            continue
            except OSError:
                continue
        return total

    @staticmethod
    def _archive_cutoff_stamp(cutoff: datetime | None) -> str:
        if cutoff:
            return cutoff.strftime("%Y%m%d")
        return datetime.now().strftime("%Y%m%d_%H%M")

    @staticmethod
    def _rename_archive_with_cutoff(archive_root: Path, cutoff: datetime | None = None) -> Path:
        parent = archive_root.parent
        name = archive_root.name
        if not ("资料归档" in name or "持续整理" in name or re.search(r"至\d{8}(?:_\d{4})?", name)):
            return archive_root
        new_name = re.sub(r"_?至\d{8}(?:_\d{4})?", "", name)
        new_name = re.sub(r"_?持续整理", "", new_name)
        if not new_name:
            new_name = "资料归档"
        target = parent / f"{new_name}_至{Organizer._archive_cutoff_stamp(cutoff)}"
        if target == archive_root:
            return archive_root
        if target.exists():
            i = 1
            while (parent / f"{target.name}_重复{i}").exists():
                i += 1
            target = parent / f"{target.name}_重复{i}"
        archive_root.rename(target)
        return target

    def _write_marker(self, archive_root: Path) -> None:
        marker = {
            "app": APP_NAME,
            "created_or_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rules_hash": self.classifier.rules_hash,
            "rules_version": self.classifier.rules_version,
            "rules_snapshot": self.classifier.effective_rules,
            "note": "此目录由科学文件整理器维护，后续可选择续整理到这里。",
        }
        (archive_root / ARCHIVE_MARKER).write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _read_marker(archive_root: Path) -> dict | None:
        marker_path = archive_root / ARCHIVE_MARKER
        if not marker_path.exists():
            return None
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return marker if isinstance(marker, dict) else None

    @staticmethod
    def _write_readme(archive_root: Path, plan: list[PlanItem]) -> None:
        counts: dict[str, int] = {}
        for item in plan:
            top = item.category.split("/")[0]
            counts[top] = counts.get(top, 0) + 1
        lines = [
            "# 归档说明",
            "",
            f"最近整理时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## 这套整理逻辑",
            "- 先看项目、来源、用途等语义线索，再结合扩展名、修改月份和文件夹结构。",
            "- 支持 AI 素材、设计资产、照片截图、3D/CAD、影视音频、文档合同、数据表格、代码脚本、软件安装包等通用场景。",
            "- 每条记录带有可信度和判断依据；低可信度内容会保守进入“旧文件夹与未归类”。",
            "",
            "## 本次分类统计",
        ]
        lines.extend(f"- {key}：{value} 项" for key, value in sorted(counts.items()))
        (archive_root / "归档说明.md").write_text("\n".join(lines), encoding="utf-8")


class OrganizerApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1320x820")
        self.root.minsize(1080, 700)
        self.root.configure(bg="#f5f7fb")
        self.root.tk.call("tk", "scaling", 1.25)
        self.organizer = Organizer()
        self.plan: list[PlanItem] = []
        self.archive_root: Path | None = None

        self.folder_var = StringVar(value="")
        self.mode_var = StringVar(value="续整理到已有归档")
        self.date_mode_var = StringVar(value="不限日期")
        now = datetime.now()
        self.cutoff_year_var = StringVar(value=str(now.year))
        self.cutoff_month_var = StringVar(value=f"{now.month:02d}")
        self.cutoff_day_var = StringVar(value=f"{now.day:02d}")
        self.folder_scope_var = StringVar(value="包含子文件夹")
        self.summary_var = StringVar(value="等待预览")
        self.destination_var = StringVar(value="尚未选择目标")
        self.low_confidence_var = StringVar(value="0 个需留意")
        self.status_var = StringVar(value="选择文件夹后点“预览整理”。")

        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        else:
            style.theme_use("default")
        base_font = ("Microsoft YaHei UI", 11)
        style.configure(".", font=base_font, background="#f5f7fb", foreground="#172033")
        style.configure("App.TFrame", background="#f5f7fb")
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("Hero.TFrame", background="#172033", relief="flat")
        style.configure("HeroTitle.TLabel", background="#172033", foreground="#ffffff", font=("Microsoft YaHei UI", 22, "bold"))
        style.configure("HeroSub.TLabel", background="#172033", foreground="#cbd5e1", font=("Microsoft YaHei UI", 11))
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#172033", font=("Microsoft YaHei UI", 12, "bold"))
        style.configure("CardValue.TLabel", background="#ffffff", foreground="#2563eb", font=("Microsoft YaHei UI", 16, "bold"))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#64748b", font=("Microsoft YaHei UI", 10))
        style.configure("Primary.TButton", font=("Microsoft YaHei UI", 11, "bold"), padding=(18, 10))
        style.configure("TButton", font=base_font, padding=(14, 9))
        style.configure("TCombobox", font=base_font, padding=(6, 4))
        style.configure("Treeview", font=base_font, rowheight=34, background="#ffffff", fieldbackground="#ffffff", borderwidth=0)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 11, "bold"), background="#eef2ff", foreground="#172033")

        outer = ttk.Frame(self.root, padding=18, style="App.TFrame")
        outer.pack(fill="both", expand=True)

        hero = ttk.Frame(outer, padding=18, style="Hero.TFrame")
        hero.pack(fill="x", pady=(0, 12))
        ttk.Label(hero, text="科学文件整理器", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(
            hero,
            text="预览优先、解释可见、低打扰默认值。把散乱下载变成可继续生长的资料库。",
            style="HeroSub.TLabel",
        ).pack(anchor="w", pady=(6, 0))

        dashboard = ttk.Frame(outer, style="App.TFrame")
        dashboard.pack(fill="x", pady=(0, 12))
        self._stat_card(dashboard, "预览项目", self.summary_var, 0)
        self._stat_card(dashboard, "目标归档", self.destination_var, 1)
        self._stat_card(dashboard, "低可信度", self.low_confidence_var, 2)
        dashboard.columnconfigure((0, 1, 2), weight=1, uniform="cards")

        top = ttk.Frame(outer, padding=14, style="Card.TFrame")
        top.pack(fill="x")

        ttk.Label(top, text="整理设置", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
        ttk.Label(top, text="要整理的文件夹", background="#ffffff").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(top, textvariable=self.folder_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(top, text="选择文件夹", command=self.choose_folder).grid(row=1, column=2, padx=(8, 0), pady=4)

        ttk.Label(top, text="整理方式", background="#ffffff").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        modes = ("续整理到已有归档", "新建本次归档", "按月份归档")
        ttk.Combobox(top, textvariable=self.mode_var, values=modes, state="readonly", width=22).grid(
            row=2, column=1, sticky="w", pady=4
        )

        ttk.Label(top, text="子文件夹", background="#ffffff").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            top,
            textvariable=self.folder_scope_var,
            values=("包含子文件夹", "只整理散落文件"),
            state="readonly",
            width=18,
        ).grid(row=3, column=1, sticky="w", pady=4)
        ttk.Label(top, text="包含子文件夹：把项目文件夹整体归档；只整理散落文件：不移动任何文件夹。", style="Muted.TLabel").grid(row=3, column=1, padx=(180, 0), sticky="w")

        ttk.Label(top, text="日期范围", background="#ffffff").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            top,
            textvariable=self.date_mode_var,
            values=("不限日期", "只整理此日期之前"),
            state="readonly",
            width=18,
        ).grid(row=4, column=1, sticky="w", pady=4)
        ttk.Spinbox(top, from_=2000, to=2100, textvariable=self.cutoff_year_var, width=6, format="%.0f").grid(row=4, column=1, padx=(180, 0), sticky="w")
        ttk.Label(top, text="年", background="#ffffff").grid(row=4, column=1, padx=(242, 0), sticky="w")
        ttk.Spinbox(top, from_=1, to=12, textvariable=self.cutoff_month_var, width=4, format="%02.0f").grid(row=4, column=1, padx=(270, 0), sticky="w")
        ttk.Label(top, text="月", background="#ffffff").grid(row=4, column=1, padx=(318, 0), sticky="w")
        ttk.Spinbox(top, from_=1, to=31, textvariable=self.cutoff_day_var, width=4, format="%02.0f").grid(row=4, column=1, padx=(346, 0), sticky="w")
        ttk.Label(top, text="日", background="#ffffff").grid(row=4, column=1, padx=(394, 0), sticky="w")

        buttons = ttk.Frame(top)
        buttons.grid(row=1, column=3, rowspan=4, padx=(14, 0), sticky="nsew")
        ttk.Button(buttons, text="预览整理", command=self.preview, style="Primary.TButton").pack(fill="x", pady=(0, 8))
        ttk.Button(buttons, text="执行移动", command=self.execute).pack(fill="x", pady=(0, 8))
        ttk.Button(buttons, text="恢复上次整理", command=self.undo_last).pack(fill="x")

        top.columnconfigure(1, weight=1)

        help_text = (
            "默认推荐“续整理到已有归档”。程序会跳过已有归档目录，只处理新散件；低可信度项目会显示出来，方便你扫一眼。"
        )
        ttk.Label(outer, text=help_text, wraplength=1080, background="#f5f7fb", foreground="#475569").pack(fill="x", pady=(10, 8))

        table_frame = ttk.Frame(outer, padding=10, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)
        columns = ("name", "category", "confidence", "reason", "date", "size")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.table.heading("name", text="文件/文件夹")
        self.table.heading("category", text="归档分类")
        self.table.heading("confidence", text="可信度")
        self.table.heading("reason", text="判断依据")
        self.table.heading("date", text="修改时间")
        self.table.heading("size", text="大小")
        self.table.column("name", width=230)
        self.table.column("category", width=310)
        self.table.column("confidence", width=70, anchor="center")
        self.table.column("reason", width=300)
        self.table.column("date", width=140)
        self.table.column("size", width=80, anchor="e")
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=yscroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        ttk.Label(outer, textvariable=self.status_var).pack(fill="x", pady=(8, 0))

    def _stat_card(self, parent: ttk.Frame, title: str, value_var: StringVar, column: int) -> None:
        card = ttk.Frame(parent, padding=14, style="Card.TFrame")
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        ttk.Label(card, text=title, style="Muted.TLabel").pack(anchor="w")
        ttk.Label(card, textvariable=value_var, style="CardValue.TLabel").pack(anchor="w", pady=(4, 0))

    def choose_folder(self) -> None:
        folder = filedialog.askdirectory(title="选择要整理的文件夹")
        if folder:
            self.folder_var.set(folder)

    def preview(self) -> None:
        folder = self.folder_var.get().strip()
        mode = self.mode_var.get()
        include_folders = self.folder_scope_var.get() == "包含子文件夹"
        cutoff_text = f"{self.cutoff_year_var.get()}-{self.cutoff_month_var.get()}-{self.cutoff_day_var.get()}"
        cutoff_enabled = self.date_mode_var.get() == "只整理此日期之前"
        self._run_worker(
            self._preview_worker,
            folder,
            mode,
            include_folders,
            cutoff_enabled,
            cutoff_text,
        )

    def execute(self) -> None:
        if not self.plan or not self.archive_root:
            messagebox.showinfo(APP_NAME, "请先预览整理。")
            return
        if not messagebox.askyesno(APP_NAME, f"确认移动 {len(self.plan)} 个项目？\n\n目标：{self.archive_root}"):
            return
        self._run_worker(self._execute_worker)

    def undo_last(self) -> None:
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showinfo(APP_NAME, "请先选择要恢复的原文件夹。")
            return
        root_path = Path(folder)
        archive = self.archive_root or self.organizer._find_existing_archive(root_path)
        target_text = str(archive) if archive else "最近的归档目录"
        if not messagebox.askyesno(APP_NAME, f"确认恢复上次整理？\n\n将从 {target_text} 读取恢复记录。"):
            return
        self._run_worker(self._undo_worker, folder)

    def _preview_worker(
        self,
        folder: str,
        mode: str,
        include_folders: bool,
        cutoff_enabled: bool,
        cutoff_text: str,
    ) -> None:
        if not folder:
            self._info("请先选择文件夹。")
            return
        root_path = Path(folder)
        if not root_path.exists() or not root_path.is_dir():
            self._info("选择的路径不是有效文件夹。")
            return
        cutoff = None
        if cutoff_enabled:
            try:
                cutoff = datetime.strptime(cutoff_text, "%Y-%m-%d")
            except ValueError:
                self._info("日期不正确，请检查年月日，例如 2 月最多 29 天。")
                return
        archive_root, plan = self.organizer.build_plan(
            root_path,
            mode,
            cutoff,
            include_folders,
        )
        self.archive_root = archive_root
        self.plan = plan
        self.root.after(0, self._fill_table)

    def _execute_worker(self) -> None:
        assert self.archive_root is not None
        try:
            log_path = self.organizer.execute_plan(self.archive_root, self.plan)
        except Exception as exc:
            self._info(f"执行失败：{exc}")
            return
        self.plan = []
        self.root.after(0, self._fill_table)
        self._info(f"完成。整理清单已生成：{log_path}")

    def _undo_worker(self, folder: str) -> None:
        try:
            restored, log_path = self.organizer.undo_latest(Path(folder), self.archive_root)
        except Exception as exc:
            self._info(f"恢复失败：{exc}")
            return
        if restored == 0:
            self._info("没有找到可恢复的上次整理记录。")
            return
        self.plan = []
        self.root.after(0, self._fill_table)
        self._info(f"已恢复 {restored} 个项目。恢复记录已标记：{log_path}")

    def _fill_table(self) -> None:
        for row in self.table.get_children():
            self.table.delete(row)
        for item in self.plan:
            self.table.insert(
                "",
                "end",
                values=(
                    item.source.name,
                    item.category,
                    f"{item.confidence}%",
                    item.reason,
                    item.modified_at.strftime("%Y-%m-%d %H:%M"),
                    self._format_size(item.size_bytes),
                ),
            )
        if self.archive_root:
            total_size = sum(item.size_bytes for item in self.plan)
            low_count = sum(1 for item in self.plan if item.confidence < 65)
            self.summary_var.set(f"{len(self.plan)} 项 / {self._format_size(total_size)}")
            self.destination_var.set(self.archive_root.name)
            self.low_confidence_var.set(f"{low_count} 个需留意")
            self.status_var.set(f"预览完成：{len(self.plan)} 个项目将归档到 {self.archive_root}")
        else:
            self.summary_var.set("0 项")
            self.destination_var.set("尚未选择目标")
            self.low_confidence_var.set("0 个需留意")
            self.status_var.set("没有可整理项目。")

    def _run_worker(self, target, *args) -> None:
        self.status_var.set("正在处理，请稍等...")
        threading.Thread(target=target, args=args, daemon=True).start()

    def _info(self, text: str) -> None:
        self.root.after(0, lambda: self.status_var.set(text))

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1024 ** 3:
            return f"{size / 1024 ** 3:.2f} GB"
        if size >= 1024 ** 2:
            return f"{size / 1024 ** 2:.2f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"


class ModernOrganizerApp:
    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1360x840")
        self.root.minsize(1120, 720)

        self.settings = load_app_settings()
        ctk.set_appearance_mode(self.settings.get("appearance", "light"))
        self.organizer = Organizer()
        self.plan: list[PlanItem] = []
        self.archive_root: Path | None = None
        self.plan_cutoff: datetime | None = None
        self.busy = False
        self.action_buttons: list[ctk.CTkButton] = []
        self._filter_mode: str = "default"  # "default" | "需留意" | "失败"
        self.reclassify_archive_on_execute = False
        self.reclassify_result: MoveResult | None = None

        now = datetime.now()
        self.folder_var = ctk.StringVar(value="")
        self.mode_var = ctk.StringVar(value="续整理到已有归档")
        self.date_mode_var = ctk.StringVar(value="不限日期")
        self.cutoff_year_var = ctk.StringVar(value=str(now.year))
        self.cutoff_month_var = ctk.StringVar(value=f"{now.month:02d}")
        self.cutoff_day_var = ctk.StringVar(value=f"{now.day:02d}")
        self.include_folders_var = ctk.BooleanVar(value=True)
        self.summary_var = ctk.StringVar(value="等待预览")
        self.destination_var = ctk.StringVar(value="尚未选择")
        self.low_confidence_var = ctk.StringVar(value="0 个需留意")
        self.failure_var = ctk.StringVar(value="0 个失败")
        self.status_var = ctk.StringVar(value="先选文件夹，再预览，确认后整理。")
        self.rule_textboxes: dict[str, ctk.CTkTextbox] = {}
        self.ai_rule_textbox: ctk.CTkTextbox | None = None
        self.ai_enabled_var = ctk.BooleanVar(value=bool(self.settings.get("ai", {}).get("enabled", False)))
        self.ai_provider_var = ctk.StringVar(value=self.settings.get("ai", {}).get("provider", "DeepSeek"))
        self.ai_base_url_var = ctk.StringVar(value=self.settings.get("ai", {}).get("base_url", AI_PROVIDER_PRESETS["DeepSeek"]))
        self.ai_key_var = ctk.StringVar(value=self.settings.get("ai", {}).get("api_key", ""))
        self.ai_model_var = ctk.StringVar(value=self.settings.get("ai", {}).get("model", ""))
        self.appearance_var = ctk.StringVar(value=self.settings.get("appearance", "light"))

        self._build_ui()
        self._refresh_day_choices()

    def _build_ui(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.configure(fg_color=COLORS["app_bg"])

        control = ctk.CTkFrame(self.root, fg_color=COLORS["panel"], corner_radius=12)
        control.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 12))
        control.grid_columnconfigure(0, weight=1)

        # ── 第一层：标题区域 ──────────────────────────────────────────
        title_row = ctk.CTkFrame(control, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 0))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            title_row,
            text="科学文件整理器",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=24, weight="bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            title_row,
            textvariable=self.status_var,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            text_color=COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.settings_button = ctk.CTkButton(
            title_row,
            text="⚙ 高级设置",
            width=110,
            height=34,
            fg_color="#eef2ff",
            hover_color="#dbeafe",
            text_color="#175cd3",
            command=self.open_settings_dialog,
        )
        self.settings_button.grid(row=0, column=1, rowspan=2, sticky="ne", padx=(12, 0))

        # ── 第二层：文件夹全宽输入区 ──────────────────────────────────
        folder_row = ctk.CTkFrame(control, fg_color="transparent")
        folder_row.grid(row=1, column=0, sticky="ew", padx=18, pady=(14, 0))
        folder_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(folder_row, text="要整理的文件夹", font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"), text_color=COLORS["subtle"]).grid(row=0, column=0, sticky="w", pady=(0, 6))
        input_row = ctk.CTkFrame(folder_row, fg_color="transparent")
        input_row.grid(row=1, column=0, sticky="ew")
        input_row.grid_columnconfigure(0, weight=1)
        self.folder_entry = ctk.CTkEntry(input_row, textvariable=self.folder_var, height=38, placeholder_text="选择下载、桌面或任意资料夹")
        self.folder_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(input_row, text="选择", width=70, height=38, command=self.choose_folder).grid(row=0, column=1)

        # ── 第三层：策略与过滤区（左：方式+子文件夹  右：日期） ────
        strategy_row = ctk.CTkFrame(control, fg_color="transparent")
        strategy_row.grid(row=2, column=0, sticky="ew", padx=18, pady=(14, 0))
        strategy_row.grid_columnconfigure(0, weight=1, uniform="settings")
        strategy_row.grid_columnconfigure(1, weight=1, uniform="settings")
        strategy_row.grid_rowconfigure(0, weight=1)

        left_group = ctk.CTkFrame(strategy_row, fg_color=COLORS["panel_soft"], corner_radius=8)
        left_group.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_group.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(left_group, text="整理方式", font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"), text_color=COLORS["subtle"]).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.mode_menu = ctk.CTkOptionMenu(left_group, values=["续整理到已有归档", "新建本次归档", "按月份归档"], variable=self.mode_var, height=38)
        self.mode_menu.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 10))
        self.scope_switch = ctk.CTkSwitch(left_group, text="包含子文件夹", variable=self.include_folders_var, font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"))
        self.scope_switch.grid(row=2, column=0, sticky="w", padx=14, pady=(0, 4))
        ctk.CTkLabel(
            left_group,
            text="开启后把子文件夹也作为整体移动；关闭后只整理当前目录下的散落文件。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
            text_color=COLORS["muted"],
            wraplength=560,
            justify="left",
        ).grid(row=3, column=0, sticky="w", padx=14, pady=(0, 12))

        right_group = ctk.CTkFrame(strategy_row, fg_color=COLORS["panel_soft"], corner_radius=8)
        right_group.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_group.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(right_group, text="日期范围", font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"), text_color=COLORS["subtle"]).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 6))
        self.date_menu = ctk.CTkSegmentedButton(right_group, values=["不限日期", "只整理此日期之前"], variable=self.date_mode_var, height=38)
        self.date_menu.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 10))

        date_row = ctk.CTkFrame(right_group, fg_color="transparent")
        date_row.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 8))
        date_row.grid_columnconfigure(1, weight=1)
        months = [f"{m:02d}" for m in range(1, 13)]
        self.year_minus_button = ctk.CTkButton(date_row, text="-", width=30, height=36, fg_color=("#e5e7eb", "#334155"), hover_color=("#d0d5dd", "#475569"), text_color=COLORS["subtle"], command=lambda: self._step_year(-1))
        self.year_entry = ctk.CTkEntry(date_row, textvariable=self.cutoff_year_var, width=72, height=36, justify="center")
        self.year_plus_button = ctk.CTkButton(date_row, text="+", width=30, height=36, fg_color=("#e5e7eb", "#334155"), hover_color=("#d0d5dd", "#475569"), text_color=COLORS["subtle"], command=lambda: self._step_year(1))
        self.month_menu = ctk.CTkOptionMenu(date_row, values=months, variable=self.cutoff_month_var, width=70, height=36, command=lambda _: self._refresh_day_choices())
        self.day_menu = ctk.CTkOptionMenu(date_row, values=[f"{d:02d}" for d in range(1, 32)], variable=self.cutoff_day_var, width=70, height=36)
        self.year_minus_button.grid(row=0, column=0)
        self.year_entry.grid(row=0, column=1, sticky="ew", padx=4)
        self.year_plus_button.grid(row=0, column=2, padx=(0, 8))
        self.month_menu.grid(row=0, column=3, padx=(0, 8))
        self.day_menu.grid(row=0, column=4)
        ctk.CTkLabel(
            right_group,
            text="选择截止日期时，只整理早于该日期的内容；不限日期则整理当前可整理内容。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
            text_color=COLORS["muted"],
            wraplength=560,
            justify="left",
        ).grid(row=3, column=0, sticky="w", padx=14, pady=(0, 12))

        # ── 第四层：状态指标 + 操作按钮 ─────────────────────────────
        bottom_row = ctk.CTkFrame(control, fg_color="transparent")
        bottom_row.grid(row=3, column=0, sticky="ew", padx=18, pady=(14, 0))
        bottom_row.grid_columnconfigure(0, weight=1)

        # 左侧：统计面板
        metrics = ctk.CTkFrame(bottom_row, fg_color="transparent")
        metrics.grid(row=0, column=0, sticky="w")
        for col in range(4):
            metrics.grid_columnconfigure(col, weight=1, uniform="metric")
        self._metric_chip(metrics, "预览", self.summary_var, 0, COLORS["blue_soft"], ("#175cd3", "#bfdbfe"))
        self._metric_chip(metrics, "归档", self.destination_var, 1, COLORS["purple_soft"], ("#7a5af8", "#ddd6fe"))
        self._metric_chip(metrics, "需留意", self.low_confidence_var, 2, COLORS["amber_soft"], ("#b45309", "#fde68a"), clickable=True)
        self._metric_chip(metrics, "失败", self.failure_var, 3, COLORS["red_soft"], ("#d92d20", "#fecaca"), clickable=True)

        # 右侧：操作按钮组
        action_row = ctk.CTkFrame(bottom_row, fg_color="transparent")
        action_row.grid(row=0, column=1, sticky="e")
        self.main_preview_button = ctk.CTkButton(action_row, text="预览", width=120, height=44, fg_color="#2563eb", hover_color="#1d4ed8", command=self.preview)
        self.main_preview_button.pack(side="left", padx=(0, 10))
        self.main_execute_button = ctk.CTkButton(action_row, text="执行整理", width=140, height=44, fg_color="#16a34a", hover_color="#15803d", command=self.execute)
        self.main_execute_button.pack(side="left", padx=(0, 10))
        self.undo_button = ctk.CTkButton(action_row, text="恢复记录", width=110, height=44, fg_color="#f59e0b", hover_color="#d97706", command=self.open_recovery_dialog)
        self.undo_button.pack(side="left")
        self.action_buttons.extend([self.main_preview_button, self.main_execute_button, self.undo_button])

        # ── 进度条（衔接下方列表区） ────────────────────────────────
        self.progress = ctk.CTkProgressBar(control, height=6, mode="indeterminate")
        self.progress.grid(row=4, column=0, sticky="ew", padx=18, pady=(14, 14))
        self.progress.set(0)

        # ── 数据列表区（原生 Canvas+Scrollbar，避免 CTkScrollableFrame 花屏） ─
        list_container = ctk.CTkFrame(self.root, fg_color=COLORS["panel"], corner_radius=10)
        list_container.grid(row=1, column=0, sticky="nsew", padx=22, pady=(0, 22))
        list_container.grid_rowconfigure(0, weight=1)
        list_container.grid_columnconfigure(0, weight=1)

        self._list_canvas = tk.Canvas(list_container, bg=self._theme_color(COLORS["panel"]), highlightthickness=0, bd=0)
        self._list_scrollbar = ctk.CTkScrollbar(list_container, command=self._list_canvas.yview)
        self._list_canvas.configure(yscrollcommand=self._list_scrollbar.set)
        self._list_canvas.grid(row=0, column=0, sticky="nsew", padx=(14, 0), pady=14)
        self._list_scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 6), pady=14)

        self.list_frame = ctk.CTkFrame(self._list_canvas, fg_color=COLORS["panel"])
        self._list_window = self._list_canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.list_frame.bind("<Configure>", self._on_list_frame_configure)
        self._list_canvas.bind("<Configure>", self._on_list_canvas_configure)

        # 鼠标滚轮绑定到 canvas
        self._list_canvas.bind_all("<MouseWheel>", self._on_list_mousewheel)

        for col, weight in enumerate([4, 4, 1, 1, 5]):
            self.list_frame.grid_columnconfigure(col, weight=weight)
        self._render_empty_state()

    def _side_label(self, text: str, row: int) -> None:
        ctk.CTkLabel(
            self.sidebar,
            text=text,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"),
            text_color=COLORS["subtle"],
        ).grid(row=row, column=0, sticky="w", padx=24, pady=(0, 8))

    def _theme_color(self, color: str | tuple[str, str]) -> str:
        if isinstance(color, tuple):
            return color[1] if ctk.get_appearance_mode().lower() == "dark" else color[0]
        return color

    def _stat_card(self, parent: ctk.CTkFrame, title: str, variable: ctk.StringVar, col: int, color: str) -> None:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=10)
        frame.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 10, 0))
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(family="Microsoft YaHei UI", size=13), text_color=COLORS["muted"]).pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(frame, textvariable=variable, font=ctk.CTkFont(family="Microsoft YaHei UI", size=19, weight="bold"), text_color=color).pack(anchor="w", padx=16, pady=(0, 14))

    def _metric_chip(self, parent: ctk.CTkFrame, title: str, variable: ctk.StringVar, col: int, bg: str, color: str, clickable: bool = False) -> None:
        frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=8)
        frame.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0))
        title_label = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(family="Microsoft YaHei UI", size=12), text_color=COLORS["muted"])
        title_label.pack(anchor="w", padx=12, pady=(8, 0))
        value_label = ctk.CTkLabel(frame, textvariable=variable, font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"), text_color=color)
        value_label.pack(anchor="w", padx=12, pady=(0, 8))
        if clickable:
            # 绑定整个 frame 的鼠标事件
            for widget in (frame, title_label, value_label):
                widget.configure(cursor="hand2")
                widget.bind("<Button-1>", lambda e, t=title: self._filter_by_metric(t))

    def choose_folder(self) -> None:
        selected = filedialog.askdirectory(title="选择要整理的文件夹")
        if selected:
            self.folder_var.set(selected)

    def preview(self) -> None:
        root = self._selected_root()
        if not root:
            return
        if not self._resolve_rule_change(root):
            return
        self.status_var.set("正在分析文件用途、来源、时间和项目关联...")
        self._run_worker(lambda: self._preview_worker(root))

    def execute(self) -> None:
        if self.busy:
            return
        if not self.plan or not self.archive_root:
            messagebox.showwarning(APP_NAME, "请先预览，确认整理方案后再开始。", parent=self.root)
            return
        if not messagebox.askyesno(APP_NAME, f"确认移动 {len(self.plan)} 个项目吗？\n程序会生成恢复记录，可一键恢复。", parent=self.root):
            return
        self.status_var.set("正在移动文件；被占用或无权限的项目会跳过并记录。")
        self._run_worker(self._execute_worker)

    def undo_last(self) -> None:
        root = self._selected_root()
        if not root:
            return
        if not messagebox.askyesno(APP_NAME, "将按最新恢复记录把文件移回原位置，是否继续？", parent=self.root):
            return
        self.status_var.set("正在恢复最近一次整理...")
        self._run_worker(lambda: self._undo_worker(root))

    def open_recovery_dialog(self) -> None:
        root = self._selected_root()
        if not root:
            return
        logs = self.organizer.list_recovery_logs(root)
        if not logs:
            messagebox.showinfo(APP_NAME, "当前文件夹下没有找到可用的恢复记录。", parent=self.root)
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("选择恢复记录")
        dialog.geometry("820x520")
        dialog.minsize(700, 420)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            dialog,
            text="恢复记录",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=22, weight="bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 4))
        ctk.CTkLabel(
            dialog,
            text="已读取当前文件夹下的所有恢复记录，最新的排在最上面。橙色按钮代表回退操作。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            text_color=COLORS["muted"],
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(52, 12))

        body = ctk.CTkScrollableFrame(dialog, fg_color=COLORS["panel"], corner_radius=10)
        body.grid(row=1, column=0, sticky="nsew", padx=22, pady=(8, 22))
        body.grid_columnconfigure(0, weight=1)

        for row, log in enumerate(logs):
            item = ctk.CTkFrame(body, fg_color=COLORS["amber_soft"] if row == 0 else COLORS["panel_soft"], corner_radius=8)
            item.grid(row=row, column=0, sticky="ew", padx=8, pady=(8, 0))
            item.grid_columnconfigure(0, weight=1)
            title = f"{log.modified_at.strftime('%Y-%m-%d %H:%M')}  ·  {log.item_count} 个项目"
            ctk.CTkLabel(item, text=title, font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold"), text_color=COLORS["text"]).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 2))
            ctk.CTkLabel(item, text=str(log.path), font=ctk.CTkFont(family="Microsoft YaHei UI", size=12), text_color=COLORS["muted"], wraplength=560, justify="left").grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))
            ctk.CTkButton(
                item,
                text="恢复这次",
                width=100,
                height=36,
                fg_color="#f59e0b",
                hover_color="#d97706",
                command=lambda p=log.path, d=dialog: self._confirm_restore_log(p, d),
            ).grid(row=0, column=1, rowspan=2, sticky="e", padx=14, pady=10)

    def _confirm_restore_log(self, log_path: Path, dialog: ctk.CTkToplevel) -> None:
        if not messagebox.askyesno(APP_NAME, f"确认按这条恢复记录回退吗？\n{log_path}", parent=dialog):
            return
        dialog.destroy()
        self.status_var.set("正在按选择的恢复记录回退...")
        self._run_worker(lambda: self._restore_log_worker(log_path))

    def open_settings_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("高级设置")
        dialog.geometry("980x720")
        dialog.minsize(860, 620)
        dialog.transient(self.root)
        dialog.protocol("WM_DELETE_WINDOW", lambda d=dialog: self._close_dialog(d))
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            dialog,
            text="高级设置",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=24, weight="bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w", padx=22, pady=(18, 4))

        tabs = ctk.CTkTabview(dialog, fg_color=COLORS["panel"], corner_radius=10)
        tabs.grid(row=1, column=0, sticky="nsew", padx=22, pady=(8, 22))
        rules_tab = tabs.add("整理规则")
        ai_tab = tabs.add("AI增强")
        ui_tab = tabs.add("外观")
        self._build_rules_tab(rules_tab, dialog)
        self._build_ai_tab(ai_tab, dialog)
        self._build_appearance_tab(ui_tab, dialog)

    def _close_dialog(self, dialog: ctk.CTkToplevel) -> None:
        try:
            dialog.grab_release()
        except tk.TclError:
            pass
        dialog.destroy()

    def _build_rules_tab(self, parent: ctk.CTkFrame, dialog: ctk.CTkToplevel) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            parent,
            text="这里显示当前正在生效的默认规则和本机学习规则。多个词可以用中文逗号、英文逗号、顿号、分号、竖线或换行分隔；保存后会生成带时间戳的新规则版本。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
        ).grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))

        body = ctk.CTkScrollableFrame(parent, fg_color=COLORS["panel_soft"], corner_radius=8)
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))
        body.grid_columnconfigure((0, 1), weight=1, uniform="rules")
        self.rule_textboxes = {}
        effective_rules = self.organizer.classifier.effective_rules
        effective_keywords = effective_rules.get("keywords", {}) if isinstance(effective_rules.get("keywords"), dict) else {}
        for index, (key, label) in enumerate(RULE_FIELD_LABELS.items()):
            card = ctk.CTkFrame(body, fg_color=COLORS["card"], corner_radius=8)
            card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=8, pady=8)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"), text_color=COLORS["subtle"]).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
            box = ctk.CTkTextbox(card, height=72, font=ctk.CTkFont(family="Microsoft YaHei UI", size=12))
            box.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
            values = effective_keywords.get(key, [])
            if values:
                box.insert("1.0", join_rule_values(values))
            self.rule_textboxes[key] = box

        ai_row = (len(RULE_FIELD_LABELS) + 1) // 2
        ai_card = ctk.CTkFrame(body, fg_color=COLORS["card"], corner_radius=8)
        ai_card.grid(row=ai_row, column=0, columnspan=2, sticky="nsew", padx=8, pady=8)
        ai_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            ai_card,
            text="AI 学到的规则",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"),
            text_color=COLORS["subtle"],
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            ai_card,
            text="每行一条：关键词或正则 => 中文分类路径。可以微调，也可以删掉不准的规则；导出规则时会一起导出。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=12),
            text_color=COLORS["muted"],
            wraplength=800,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 6))
        self.ai_rule_textbox = ctk.CTkTextbox(ai_card, height=110, font=ctk.CTkFont(family="Microsoft YaHei UI", size=12))
        self.ai_rule_textbox.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.ai_rule_textbox.insert("1.0", self._format_ai_category_patterns(effective_rules.get("ai_category_patterns", [])))

        actions = ctk.CTkFrame(parent, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        ctk.CTkButton(actions, text="保存为新版规则", width=130, command=lambda: self._save_rules_from_dialog(dialog)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="导入规则文件", width=120, fg_color="#475467", hover_color="#344054", command=lambda: self._import_rules_file(dialog)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="导出当前规则", width=120, fg_color="#475467", hover_color="#344054", command=lambda: self._export_rules_file(dialog)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="恢复默认规则", width=120, fg_color="#dc2626", hover_color="#b91c1c", command=lambda: self._reset_rules(dialog)).pack(side="left")

    def _build_ai_tab(self, parent: ctk.CTkFrame, dialog: ctk.CTkToplevel) -> None:
        parent.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            parent,
            text="AI 增强默认关闭。开启后会先用本地规则预整理，再把待确认、泛分类和疑似被拆散的项目交给 AI 复核；高可信结果会沉淀成本机规则，之后可在“整理规则”页查看、微调和导出。密钥只保存在本机设置文件中。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="ew", padx=16, pady=(16, 14))
        ctk.CTkSwitch(parent, text="启用 AI 增强", variable=self.ai_enabled_var, font=ctk.CTkFont(family="Microsoft YaHei UI", size=14, weight="bold")).grid(row=1, column=0, columnspan=3, sticky="w", padx=16, pady=(0, 12))

        ctk.CTkLabel(parent, text="平台", text_color=COLORS["subtle"]).grid(row=2, column=0, sticky="w", padx=16, pady=6)
        provider_menu = ctk.CTkOptionMenu(parent, values=list(AI_PROVIDER_PRESETS), variable=self.ai_provider_var, command=self._on_ai_provider_changed)
        provider_menu.grid(row=2, column=1, sticky="ew", padx=(0, 16), pady=6)

        ctk.CTkLabel(parent, text="接口地址", text_color=COLORS["subtle"]).grid(row=3, column=0, sticky="w", padx=16, pady=6)
        ctk.CTkEntry(parent, textvariable=self.ai_base_url_var, placeholder_text="OpenAI 兼容接口，例如 https://api.example.com/v1").grid(row=3, column=1, columnspan=2, sticky="ew", padx=(0, 16), pady=6)

        ctk.CTkLabel(parent, text="API Key", text_color=COLORS["subtle"]).grid(row=4, column=0, sticky="w", padx=16, pady=6)
        ctk.CTkEntry(parent, textvariable=self.ai_key_var, show="*", placeholder_text="只保存在本机，不会写入整理清单").grid(row=4, column=1, columnspan=2, sticky="ew", padx=(0, 16), pady=6)

        ctk.CTkLabel(parent, text="模型", text_color=COLORS["subtle"]).grid(row=5, column=0, sticky="w", padx=16, pady=6)
        self.ai_model_menu = ctk.CTkOptionMenu(parent, values=[self.ai_model_var.get() or "请先刷新模型"], variable=self.ai_model_var)
        self.ai_model_menu.grid(row=5, column=1, sticky="ew", padx=(0, 8), pady=6)
        ctk.CTkButton(parent, text="刷新模型", width=96, command=lambda: self._refresh_ai_models(dialog)).grid(row=5, column=2, sticky="e", padx=(0, 16), pady=6)

        actions = ctk.CTkFrame(parent, fg_color="transparent")
        actions.grid(row=6, column=0, columnspan=3, sticky="ew", padx=16, pady=(18, 0))
        ctk.CTkButton(actions, text="测试连接", width=110, fg_color="#2563eb", hover_color="#1d4ed8", command=lambda: self._test_ai_connection(dialog)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="保存 AI 设置", width=130, command=lambda: self._save_ai_settings(dialog)).pack(side="left")

    def _build_appearance_tab(self, parent: ctk.CTkFrame, dialog: ctk.CTkToplevel) -> None:
        parent.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            parent,
            text="选择软件外观。保存后会立即生效，并在下次启动时保持。",
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
            text_color=COLORS["muted"],
            wraplength=860,
            justify="left",
        ).grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 14))
        ctk.CTkSegmentedButton(parent, values=["light", "dark", "system"], variable=self.appearance_var).grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 16))
        ctk.CTkButton(parent, text="保存外观设置", width=130, command=lambda: self._save_appearance_settings(dialog)).grid(row=2, column=0, sticky="w", padx=16)

    def _load_local_rules(self) -> dict:
        path = runtime_dir() / LOCAL_RULES_FILE
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _format_ai_category_patterns(patterns: object) -> str:
        if not isinstance(patterns, list):
            return ""
        lines = []
        for item in patterns:
            if not isinstance(item, dict):
                continue
            pattern = str(item.get("pattern", "")).strip()
            category = str(item.get("category", "")).strip()
            if pattern and category:
                lines.append(f"{pattern} => {category}")
        return "\n".join(lines)

    @staticmethod
    def _parse_ai_category_patterns(text: str) -> list[dict]:
        patterns: list[dict] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=>" in line:
                left, right = line.split("=>", 1)
            elif "->" in line:
                left, right = line.split("->", 1)
            elif "=" in line:
                left, right = line.split("=", 1)
            else:
                continue
            pattern = left.strip()
            category = right.strip().strip("/\\")
            if not pattern or not category:
                continue
            try:
                re.compile(pattern)
            except re.error:
                pattern = re.escape(pattern)
            patterns.append({
                "pattern": pattern,
                "category": category,
                "source": "user-edited-ai-rule",
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        return patterns

    def _save_rules_from_dialog(self, dialog: ctk.CTkToplevel) -> None:
        keywords = {}
        for key, box in self.rule_textboxes.items():
            values = split_rule_text(box.get("1.0", "end"))
            if values:
                keywords[key] = values
        rules = {
            "version": timestamp_version("user-rules"),
            "description": "用户在高级设置中保存的私人规则，会自动叠加到默认规则上。",
            "keywords": keywords,
        }
        ai_patterns = self._parse_ai_category_patterns(self.ai_rule_textbox.get("1.0", "end") if self.ai_rule_textbox else "")
        if ai_patterns:
            rules["ai_category_patterns"] = ai_patterns
        (runtime_dir() / LOCAL_RULES_FILE).write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
        self._reload_rules_after_settings_change()
        messagebox.showinfo(APP_NAME, f"已保存新版规则：{rules['version']}", parent=dialog)

    def _import_rules_file(self, dialog: ctk.CTkToplevel) -> None:
        path = filedialog.askopenfilename(title="选择规则文件", filetypes=[("JSON 规则文件", "*.json"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror(APP_NAME, f"规则文件读取失败：{exc}", parent=dialog)
            return
        if not isinstance(data, dict):
            messagebox.showerror(APP_NAME, "规则文件格式不正确。", parent=dialog)
            return
        data["version"] = timestamp_version("imported-rules")
        (runtime_dir() / LOCAL_RULES_FILE).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self._reload_rules_after_settings_change()
        messagebox.showinfo(APP_NAME, f"已导入规则并生成新版本：{data['version']}", parent=dialog)
        self._close_dialog(dialog)
        self.open_settings_dialog()

    def _export_rules_file(self, dialog: ctk.CTkToplevel) -> None:
        path = filedialog.asksaveasfilename(title="导出规则文件", defaultextension=".json", filetypes=[("JSON 规则文件", "*.json")])
        if not path:
            return
        export_rules = dict(self.organizer.classifier.effective_rules)
        export_rules["version"] = timestamp_version("exported-rules")
        try:
            Path(path).write_text(json.dumps(export_rules, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"导出失败：{exc}", parent=dialog)
            return
        messagebox.showinfo(APP_NAME, "规则已导出。", parent=dialog)

    def _reset_rules(self, dialog: ctk.CTkToplevel) -> None:
        if not messagebox.askyesno(APP_NAME, "确认恢复默认规则吗？\n\n会清空你在高级设置中保存的自定义关键词，但会生成新的默认规则时间戳。", parent=dialog):
            return
        rules = {
            "version": timestamp_version("default-reset"),
            "description": "用户恢复默认规则时生成的空白叠加层，用于刷新规则时间戳。",
            "keywords": {},
        }
        (runtime_dir() / LOCAL_RULES_FILE).write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
        self._reload_rules_after_settings_change()
        messagebox.showinfo(APP_NAME, f"已恢复默认规则：{rules['version']}", parent=dialog)
        self._close_dialog(dialog)
        self.open_settings_dialog()

    def _reload_rules_after_settings_change(self) -> None:
        self.organizer = Organizer()
        self.plan = []
        self.archive_root = None
        self._render_empty_state("规则已更新", "请重新预览，新的规则会立即生效。")
        self.summary_var.set("等待预览")
        self.destination_var.set("尚未选择")
        self.low_confidence_var.set("0 个需留意")
        self.failure_var.set("0 个失败")
        self.status_var.set(f"规则已更新：{self.organizer.classifier.rules_version}")

    def _on_ai_provider_changed(self, provider: str) -> None:
        preset = AI_PROVIDER_PRESETS.get(provider, "")
        if preset:
            self.ai_base_url_var.set(preset)

    def _save_ai_settings(self, dialog: ctk.CTkToplevel) -> None:
        self.settings["ai"] = {
            "enabled": bool(self.ai_enabled_var.get()),
            "provider": self.ai_provider_var.get(),
            "base_url": self.ai_base_url_var.get().strip(),
            "api_key": self.ai_key_var.get().strip(),
            "model": self.ai_model_var.get().strip(),
        }
        save_app_settings(self.settings)
        messagebox.showinfo(APP_NAME, "AI 设置已保存。", parent=dialog)

    def _save_appearance_settings(self, dialog: ctk.CTkToplevel) -> None:
        appearance = self.appearance_var.get()
        self.settings["appearance"] = appearance
        save_app_settings(self.settings)
        self._close_dialog(dialog)
        self.root.after(80, lambda mode=appearance: self._apply_appearance_mode(mode))

    def _apply_appearance_mode(self, mode: str) -> None:
        ctk.set_appearance_mode(mode)
        if hasattr(self, "_list_canvas"):
            self._list_canvas.configure(bg=self._theme_color(COLORS["panel"]))
        self.status_var.set("外观设置已保存，已应用。")

    def _refresh_ai_models(self, dialog: ctk.CTkToplevel) -> None:
        base_url = self.ai_base_url_var.get().strip().rstrip("/")
        api_key = self.ai_key_var.get().strip()
        if not base_url or not api_key:
            messagebox.showwarning(APP_NAME, "请先填写接口地址和 API Key。", parent=dialog)
            return
        self.status_var.set("正在刷新模型列表...")
        threading.Thread(target=lambda: self._refresh_ai_models_worker(base_url, api_key, dialog), daemon=True).start()

    def _test_ai_connection(self, dialog: ctk.CTkToplevel) -> None:
        base_url = self.ai_base_url_var.get().strip().rstrip("/")
        api_key = self.ai_key_var.get().strip()
        if not base_url or not api_key:
            messagebox.showwarning(APP_NAME, "请先填写接口地址和 API Key。", parent=dialog)
            return
        self.status_var.set("正在测试 AI 连接...")
        threading.Thread(target=lambda: self._test_ai_connection_worker(base_url, api_key, dialog), daemon=True).start()

    def _test_ai_connection_worker(self, base_url: str, api_key: str, dialog: ctk.CTkToplevel) -> None:
        try:
            models = self._fetch_ai_models(base_url, api_key)
        except Exception as exc:
            self.root.after(0, lambda: self.status_var.set("AI 连接失败，请检查 Key 或接口地址。"))
            self.root.after(0, lambda: messagebox.showerror(APP_NAME, f"AI 连接失败：{exc}", parent=dialog))
            return
        self.root.after(0, lambda: self._apply_ai_models(models, dialog, tested=True))

    def _refresh_ai_models_worker(self, base_url: str, api_key: str, dialog: ctk.CTkToplevel) -> None:
        try:
            models = self._fetch_ai_models(base_url, api_key)
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror(APP_NAME, f"模型列表刷新失败：{exc}", parent=dialog))
            self.root.after(0, lambda: self.status_var.set("模型列表刷新失败。"))
            return
        self.root.after(0, lambda: self._apply_ai_models(models, dialog))

    def _fetch_ai_models(self, base_url: str, api_key: str) -> list[str]:
        url = base_url.rstrip("/") + "/models"
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
        models = [item.get("id") for item in payload.get("data", []) if isinstance(item, dict) and item.get("id")]
        if not models:
            raise RuntimeError("没有读取到可用模型")
        return models

    def _apply_ai_models(self, models: list[str], dialog: ctk.CTkToplevel, tested: bool = False) -> None:
        self.ai_model_menu.configure(values=models)
        if self.ai_model_var.get() not in models:
            self.ai_model_var.set(models[0])
        self.status_var.set("AI 连接正常，模型列表已刷新。" if tested else "模型列表已刷新。")
        messagebox.showinfo(APP_NAME, f"AI 连接正常，已读取到 {len(models)} 个模型。", parent=dialog)

    def _ai_config(self) -> dict:
        settings = load_app_settings().get("ai", {})
        return settings if isinstance(settings, dict) else {}

    def _ai_review_plan_if_enabled(self, archive_root: Path, plan: list[PlanItem]) -> tuple[list[PlanItem], str]:
        config = self._ai_config()
        if not config.get("enabled"):
            return plan, ""
        if not config.get("base_url") or not config.get("api_key") or not config.get("model"):
            self.root.after(0, lambda: messagebox.showwarning(APP_NAME, "AI 增强已开启，但接口、Key 或模型未配置完整。本次先使用本地规则。", parent=self.root))
            return plan, "AI 未配置完整，已跳过"
        suspects = self._ai_select_suspects(plan)
        if not suspects:
            return plan, "AI 检查：没有明显存疑项"
        limit = min(len(suspects), 80)
        suspects = suspects[:limit]
        corrected: dict[str, tuple[str, int, str]] = {}
        learned_rules: list[dict] = []
        batches = [suspects[i:i + 15] for i in range(0, len(suspects), 15)]
        for index, batch in enumerate(batches, start=1):
            self.root.after(0, lambda i=index, total=len(batches), n=len(batch): self.status_var.set(f"AI 正在分析存疑文件：第 {i}/{total} 批，{n} 个项目..."))
            try:
                result, rules = self._ask_ai_for_classification(batch, plan)
            except Exception as exc:
                self.root.after(0, lambda e=exc: self.status_var.set(f"AI 分析失败，已保留本地规则结果：{e}"))
                return plan, "AI 分析失败，已保留本地结果"
            corrected.update(result)
            learned_rules.extend(rules)
            self.root.after(0, lambda i=index, total=len(batches): self.status_var.set(f"AI 第 {i}/{total} 批结果已返回，正在合并分类..."))
        if not corrected and not learned_rules:
            return plan, "AI 未返回可用修正"
        new_plan = []
        changed = 0
        for item in plan:
            key = str(item.source)
            if key not in corrected:
                new_plan.append(item)
                continue
            category, confidence, reason = corrected[key]
            if not category:
                new_plan.append(item)
                continue
            dest_dir = archive_root / Path(category)
            dest = self.organizer._unique_destination(dest_dir, item.source.name)
            new_plan.append(replace(item, destination=dest, category=category, confidence=max(confidence, item.confidence, 75), reason=f"AI复核：{reason}"))
            if category != item.category:
                changed += 1
        learned_count = self._persist_ai_rule_suggestions(plan, corrected, learned_rules) if (changed or learned_rules) else 0
        self.root.after(0, lambda: self.status_var.set(f"AI 分析完成：修正 {changed} 个存疑分类，沉淀 {learned_count} 条本机规则。"))
        return new_plan, f"AI 已复核 {len(suspects)} 个存疑项，修正 {changed} 个，学习 {learned_count} 条规则"

    def _ai_select_suspects(self, plan: list[PlanItem]) -> list[PlanItem]:
        selected: list[PlanItem] = []
        seen: set[str] = set()

        def add(item: PlanItem) -> None:
            key = str(item.source)
            if key not in seen:
                seen.add(key)
                selected.append(item)

        generic_markers = (
            "普通图片素材",
            "视频文件/",
            "普通文档资料",
            "图片视频目录",
            "待确认",
            "其他散件",
            "代码配置脚本",
        )
        for item in plan:
            if item.confidence < 75 or item.category.startswith("99_") or any(marker in item.category for marker in generic_markers):
                add(item)

        project_groups: dict[str, list[PlanItem]] = {}
        for item in plan:
            if item.category.startswith("01_项目工作区/"):
                parts = item.category.split("/")
                if len(parts) > 1:
                    project_groups.setdefault(parts[1], []).append(item)
        for project, items in project_groups.items():
            if len(items) == 1 and self.organizer.classifier._looks_like_content_project(project):
                add(items[0])

        stems: dict[str, list[PlanItem]] = {}
        for item in plan:
            cleaned = self.organizer.classifier._strip_project_noise(self.organizer.classifier._normalize_project_topic(item.source.stem))
            if cleaned and len(cleaned) >= 3:
                stems.setdefault(cleaned, []).append(item)
        for items in stems.values():
            categories = {item.category for item in items}
            if len(items) >= 2 and len(categories) >= 2:
                for item in items[:8]:
                    add(item)

        selected.sort(key=lambda item: (item.confidence, item.modified_at, item.source.name.lower()))
        return selected

    def _persist_ai_rule_suggestions(self, plan: list[PlanItem], corrected: dict[str, tuple[str, int, str]], learned_rules: list[dict] | None = None) -> int:
        by_path = {str(item.source): item for item in plan}
        local_rules = self._load_local_rules()
        patterns = list(local_rules.get("ai_category_patterns", [])) if isinstance(local_rules.get("ai_category_patterns"), list) else []
        seen = {(str(item.get("pattern")), str(item.get("category"))) for item in patterns if isinstance(item, dict)}
        added = 0
        for rule in learned_rules or []:
            pattern = str(rule.get("pattern", "")).strip()
            category = str(rule.get("category", "")).strip().strip("/\\")
            try:
                confidence = int(rule.get("confidence", 85))
            except (TypeError, ValueError):
                confidence = 85
            if not self._is_safe_ai_rule(pattern, category, confidence):
                continue
            key = (pattern, category)
            if key in seen:
                continue
            patterns.append({
                "pattern": pattern,
                "category": category,
                "source": "ai-learned",
                "reason": str(rule.get("reason", "AI 根据用户文件批次学习")).strip()[:120],
                "confidence": confidence,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            seen.add(key)
            added += 1
        for item_id, (category, confidence, _reason) in corrected.items():
            source_item = by_path.get(item_id)
            if not source_item or confidence < 80 or not category or category.startswith("99_") or category == source_item.category:
                continue
            stem = source_item.source.stem.lower()
            tokens = [
                token.lower()
                for token in SmartClassifier.TOKEN_REGEX.findall(SmartClassifier.DATE_TOKEN_REGEX.sub(" ", stem))
                if token.lower() not in SmartClassifier.STOP_WORDS and (token.isascii() and len(token) >= 4)
            ][:2]
            for token in tokens:
                pattern = re.escape(token)
                key = (pattern, category)
                if key in seen:
                    continue
                patterns.append({
                    "pattern": pattern,
                    "category": category,
                    "source": "ai-reviewed",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
                seen.add(key)
                added += 1
        if not added:
            return 0
        local_rules["version"] = timestamp_version("ai-rules")
        local_rules.setdefault("description", "用户本机规则。AI 复核会把高可信、较通用的修正沉淀在这里。")
        local_rules["ai_category_patterns"] = patterns[-200:]
        (runtime_dir() / LOCAL_RULES_FILE).write_text(json.dumps(local_rules, ensure_ascii=False, indent=2), encoding="utf-8")
        self.organizer = Organizer()
        return added

    def _is_safe_ai_rule(self, pattern: str, category: str, confidence: int) -> bool:
        if confidence < 80 or not pattern or not category or category.startswith("99_"):
            return False
        if len(pattern) < 3 or len(pattern) > 120 or len(category) > 120:
            return False
        too_broad = {"视频", "图片", "文档", "素材", "文件", "下载", "image", "video", "file", "mp4", "jpg", "png"}
        if pattern.strip(".*^$").lower() in too_broad:
            return False
        try:
            re.compile(pattern)
        except re.error:
            return False
        return True

    def _ask_ai_for_classification(self, batch: list[PlanItem], plan: list[PlanItem]) -> tuple[dict[str, tuple[str, int, str]], list[dict]]:
        config = self._ai_config()
        categories = sorted({item.category for item in plan} | {item.category for item in batch})
        context_groups: dict[str, list[str]] = {}
        for item in plan:
            normalized = self.organizer.classifier._strip_project_noise(self.organizer.classifier._normalize_project_topic(item.source.stem))
            if normalized and len(normalized) >= 3:
                context_groups.setdefault(normalized, []).append(item.source.name)
        context_groups = {key: values[:8] for key, values in context_groups.items() if len(values) >= 2}
        payload_items = [
            {
                "id": str(item.source),
                "name": item.source.name,
                "path_hint": str(item.source.parent)[-120:],
                "is_dir": item.is_dir,
                "ext": item.source.suffix.lower(),
                "current_category": item.category,
                "confidence": item.confidence,
                "reason": item.reason,
            }
            for item in batch
        ]
        prompt = (
            "你是文件整理规则审查助手。目标是让软件越用越懂用户，但必须保守、可恢复、可复用。"
            "只根据文件名、父级路径、扩展名、当前分类和理由判断；不要假装读取文件内容。"
            "不要拆散 AE/PR/代码工程包；不要把合同、发票、证件、微信截图、录屏、随机哈希名硬归成项目。"
            "优先发现同一项目被版本词、编号、成片/脚本/封面/素材拆散的情况，并给出统一中文项目路径。"
            "请只输出严格 JSON 对象，格式为："
            "{\"corrections\":[{\"id\":\"...\",\"category\":\"...\",\"confidence\":85,\"reason\":\"...\"}],"
            "\"rules\":[{\"pattern\":\"可复用正则或关键词\",\"category\":\"中文分类路径\",\"confidence\":85,\"reason\":\"为什么适合长期保存\"}]}。"
            "rules 只写高可信、针对用户长期习惯的规则；不要写过宽泛规则。"
            f"\n可参考已有分类：{json.dumps(categories, ensure_ascii=False)}"
            f"\n同批相似文件线索：{json.dumps(context_groups, ensure_ascii=False)}"
            f"\n待复核项目：{json.dumps(payload_items, ensure_ascii=False)}"
        )
        response = self._call_ai_chat(prompt, config)
        payload = self._extract_json_payload(response)
        if isinstance(payload, list):
            data = payload
            rules = []
        else:
            data = payload.get("corrections", []) if isinstance(payload.get("corrections"), list) else []
            rules = payload.get("rules", []) if isinstance(payload.get("rules"), list) else []
        result: dict[str, tuple[str, int, str]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id", ""))
            category = str(item.get("category", "")).strip().strip("/\\")
            reason = str(item.get("reason", "AI 根据名称和路径上下文复核")).strip()
            try:
                confidence = int(item.get("confidence", 80))
            except (TypeError, ValueError):
                confidence = 80
            confidence = max(50, min(98, confidence))
            if item_id and category:
                result[item_id] = (category, confidence, reason)
        return result, [rule for rule in rules if isinstance(rule, dict)]

    def _call_ai_chat(self, prompt: str, config: dict) -> str:
        url = str(config.get("base_url", "")).rstrip("/") + "/chat/completions"
        body = {
            "model": config.get("model"),
            "messages": [
                {"role": "system", "content": "你只输出严格 JSON，不要输出解释。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config.get('api_key')}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]

    @staticmethod
    def _extract_json_array(text: str) -> list:
        payload = ModernOrganizerApp._extract_json_payload(text)
        return payload if isinstance(payload, list) else []

    @staticmethod
    def _extract_json_payload(text: str) -> object:
        stripped = text.strip()
        if stripped.startswith("```"):
            stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.I).strip()
            stripped = re.sub(r"```$", "", stripped).strip()
        object_start = stripped.find("{")
        array_start = stripped.find("[")
        if object_start >= 0 and (array_start < 0 or object_start < array_start):
            start = object_start
            end = stripped.rfind("}")
        else:
            start = array_start
            end = stripped.rfind("]")
        if start >= 0 and end >= start:
            stripped = stripped[start:end + 1]
        return json.loads(stripped)

    def _selected_root(self) -> Path | None:
        folder = self.folder_var.get().strip()
        if not folder:
            messagebox.showwarning(APP_NAME, "请先选择要整理的文件夹。", parent=self.root)
            return None
        root = Path(folder)
        if not root.exists() or not root.is_dir():
            messagebox.showerror(APP_NAME, "文件夹不存在。", parent=self.root)
            return None
        return root

    def _resolve_rule_change(self, root: Path) -> bool:
        self.organizer = Organizer()
        self.reclassify_archive_on_execute = False
        self.reclassify_result = None
        if self.mode_var.get() != "续整理到已有归档":
            return True
        cutoff = self._cutoff_datetime()
        archive_root = self.organizer._choose_archive_root(root, self.mode_var.get(), cutoff)
        if not archive_root.exists():
            return True
        state = self.organizer.archive_rule_state(archive_root)
        if not state["changed"]:
            return True
        if state["snapshot"]:
            choice = messagebox.askyesnocancel(
                APP_NAME,
                "检测到这个归档库使用过另一套整理规则。\n\n"
                "选择“是”：按当前新规则重新梳理已有归档，并继续整理新文件。\n"
                "选择“否”：沿用旧规则继续归类，保持旧归档口径一致。\n"
                "选择“取消”：先不整理。",
                parent=self.root,
            )
            if choice is None:
                return False
            if choice:
                self.reclassify_archive_on_execute = True
                return True
            self.organizer = Organizer(rules_data=state["snapshot"])
            return True
        choice = messagebox.askyesnocancel(
            APP_NAME,
            "检测到这个归档库没有保存当时的规则快照，或规则记录过旧。\n\n"
            "选择“是”：按当前新规则重新梳理已有归档，并继续整理新文件。\n"
            "选择“否”：只用当前规则整理新文件，不重整旧内容。\n"
            "选择“取消”：先不整理。",
            parent=self.root,
        )
        if choice is None:
            return False
        self.reclassify_archive_on_execute = bool(choice)
        return True

    def _preview_worker(self, root: Path) -> None:
        try:
            cutoff = self._cutoff_datetime()
            archive_root, plan = self.organizer.build_plan(root, self.mode_var.get(), cutoff, self.include_folders_var.get())
            plan, ai_summary = self._ai_review_plan_if_enabled(archive_root, plan)
            self.root.after(0, lambda: self._apply_preview(archive_root, plan, cutoff, ai_summary))
        except Exception as exc:
            self.root.after(0, lambda: self._error(f"预览失败：{exc}"))

    def _execute_worker(self) -> None:
        try:
            assert self.archive_root is not None
            rebuild_result = None
            if self.reclassify_archive_on_execute and self.archive_root.exists():
                rebuild_result = self.organizer.reclassify_archive(self.archive_root)
            result = self.organizer.execute_plan(self.archive_root, self.plan, self.plan_cutoff)
            self.root.after(0, lambda: self._finish_execute(result, rebuild_result))
        except Exception as exc:
            self.root.after(0, lambda: self._error(f"整理失败：{exc}"))

    def _undo_worker(self, root: Path) -> None:
        try:
            archive = self.archive_root or self.organizer._find_existing_archive(root)
            count, log = self.organizer.undo_latest(root, archive)
            self.root.after(0, lambda: self._finish_undo(count, log))
        except Exception as exc:
            self.root.after(0, lambda: self._error(f"恢复失败：{exc}"))

    def _restore_log_worker(self, log_path: Path) -> None:
        try:
            count, log = self.organizer.restore_from_log(log_path)
            self.root.after(0, lambda: self._finish_undo(count, log))
        except Exception as exc:
            self.root.after(0, lambda: self._error(f"恢复失败：{exc}"))

    def _run_worker(self, target) -> None:
        if self.busy:
            return
        self._set_busy(True)

        def wrapped() -> None:
            try:
                target()
            finally:
                self.root.after(0, lambda: self._set_busy(False))

        threading.Thread(target=wrapped, daemon=True).start()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in self.action_buttons:
            button.configure(state=state)
        if busy:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)

    def _apply_preview(self, archive_root: Path, plan: list[PlanItem], cutoff: datetime | None, ai_summary: str = "") -> None:
        self.archive_root = archive_root
        self.plan = plan
        self.plan_cutoff = cutoff
        self._filter_mode = "default"
        total_size = sum(item.size_bytes for item in plan)
        low = sum(1 for item in plan if item.confidence < 65)
        self.summary_var.set(f"{len(plan)} 项 / {self._format_size(total_size)}")
        self.destination_var.set(archive_root.name)
        self.low_confidence_var.set(f"{low} 个需留意")
        self.failure_var.set("0 个失败")
        suffix = f"；{ai_summary}" if ai_summary else ""
        self.status_var.set(f"预览完成。目标位置：{archive_root}{suffix}")
        self._render_plan(plan)

    def _finish_execute(self, result: MoveResult, rebuild_result: MoveResult | None = None) -> None:
        self.archive_root = result.archive_root
        self.plan = []
        self.failure_var.set(f"{result.failure_count} 个失败")
        total_success = result.success_count + (rebuild_result.success_count if rebuild_result else 0)
        total_failure = result.failure_count + (rebuild_result.failure_count if rebuild_result else 0)
        self.summary_var.set(f"成功 {total_success} 项")
        self.destination_var.set(result.archive_root.name)
        self.low_confidence_var.set("0 个需留意")
        rebuild_text = ""
        if rebuild_result:
            rebuild_text = f"\n已按新规则重整旧归档：{rebuild_result.success_count} 个，失败 {rebuild_result.failure_count} 个。"
        self._render_empty_state("整理完成", f"成功 {total_success} 个，失败 {total_failure} 个。清单：{result.log_path}")
        self.status_var.set(f"整理完成。成功 {total_success} 个，失败 {total_failure} 个。")
        messagebox.showinfo(APP_NAME, f"整理完成。{rebuild_text}\n新文件整理成功：{result.success_count} 个\n失败：{total_failure} 个\n清单：{result.log_path}", parent=self.root)

    def _finish_undo(self, count: int, log: Path | None) -> None:
        if count == 0:
            self.status_var.set("没有找到可恢复的记录。")
            messagebox.showinfo(APP_NAME, "没有找到可恢复的记录。", parent=self.root)
            return
        self.status_var.set(f"已恢复 {count} 个项目。恢复记录：{log}")
        messagebox.showinfo(APP_NAME, f"已恢复 {count} 个项目。", parent=self.root)

    def _error(self, message: str) -> None:
        self.status_var.set(message)
        messagebox.showerror(APP_NAME, message, parent=self.root)

    def _filter_by_metric(self, metric_title: str) -> None:
        """点击'需留意'或'失败'统计卡片时，切换排序模式并重新渲染列表。"""
        if metric_title not in ("需留意", "失败"):
            return
        if not self.plan:
            return
        # 切换模式：点击同一个则恢复默认排序
        if self._filter_mode == metric_title:
            self._filter_mode = "default"
        else:
            self._filter_mode = metric_title
        self._render_plan(self.plan)
        self._scroll_to_top()

    def _reset_filter(self) -> None:
        """恢复默认排序。"""
        self._filter_mode = "default"
        self._render_plan(self.plan)
        self._scroll_to_top()

    def _render_plan(self, plan: list[PlanItem]) -> None:
        # 根据筛选模式排序
        if self._filter_mode == "需留意":
            sorted_plan = sorted(plan, key=lambda item: (0 if item.confidence < 65 else 1, item.confidence))
        elif self._filter_mode == "失败":
            # 失败项的 confidence 为 -1 或 0（Organizer.execute_plan 标记），
            # 预览阶段按 confidence 升序排列即可
            sorted_plan = sorted(plan, key=lambda item: item.confidence)
        else:
            sorted_plan = plan

        self._clear_list()

        # 显示当前筛选模式提示
        if self._filter_mode != "default":
            filter_hint = f"🔍 筛选：{self._filter_mode} 优先显示（点击可恢复默认排序）"
            hint_label = ctk.CTkLabel(
                self.list_frame,
                text=filter_hint,
                font=ctk.CTkFont(family="Microsoft YaHei UI", size=12, weight="bold"),
                text_color="#b45309",
                fg_color="#fffbeb",
                corner_radius=6,
            )
            hint_label.grid(row=0, column=0, columnspan=5, sticky="ew", padx=12, pady=(10, 6), ipady=4)
            hint_label.bind("<Button-1>", lambda e: self._reset_filter())
            header_row = 1
        else:
            header_row = 0

        headers = ["名称", "建议位置", "可信度", "大小", "判断依据"]
        for col, text in enumerate(headers):
            ctk.CTkLabel(
                self.list_frame,
                text=text,
                font=ctk.CTkFont(family="Microsoft YaHei UI", size=13, weight="bold"),
                text_color=COLORS["subtle"],
            ).grid(row=header_row, column=col, sticky="w", padx=12, pady=(10, 8))

        visible = sorted_plan[:350]
        for row, item in enumerate(visible, start=header_row + 1):
            is_problem = item.confidence < 65
            bg = COLORS["amber_soft"] if is_problem else (COLORS["panel"] if row % 2 else COLORS["panel_soft"])
            values = [
                item.source.name,
                item.category,
                f"{item.confidence}%",
                self._format_size(item.size_bytes),
                item.reason,
            ]
            conf_color = "#d92d20" if item.confidence < 50 else ("#dc6803" if item.confidence < 75 else "#039855")
            colors = [COLORS["text"], ("#175cd3", "#bfdbfe"), conf_color, COLORS["subtle"], COLORS["muted"]]
            for col, value in enumerate(values):
                label = ctk.CTkLabel(
                    self.list_frame,
                    text=value,
                    font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
                    text_color=colors[col],
                    fg_color=bg,
                    corner_radius=0,
                    anchor="w",
                    justify="left",
                    wraplength=360 if col in (1, 4) else 240,
                )
                label.grid(row=row, column=col, sticky="ew", padx=(0, 1), pady=1, ipady=7)
        if len(sorted_plan) > len(visible):
            ctk.CTkLabel(
                self.list_frame,
                text=f"清单较长，界面仅显示前 {len(visible)} 项；完整记录会写入整理清单 CSV。",
                font=ctk.CTkFont(family="Microsoft YaHei UI", size=13),
                text_color=COLORS["muted"],
            ).grid(row=len(visible) + header_row + 1, column=0, columnspan=5, sticky="w", padx=12, pady=14)

    def _render_empty_state(self, title: str = "还没有预览", body: str = "选择文件夹后，点左侧“预览整理”，这里会显示每个文件将被放到哪里以及为什么。") -> None:
        self._clear_list()
        ctk.CTkLabel(
            self.list_frame,
            text=title,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=18, weight="bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(22, 6))
        ctk.CTkLabel(
            self.list_frame,
            text=body,
            font=ctk.CTkFont(family="Microsoft YaHei UI", size=14),
            text_color=COLORS["muted"],
            wraplength=760,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=18, pady=(0, 22))

    def _on_list_frame_configure(self, event) -> None:
        self._list_canvas.configure(scrollregion=self._list_canvas.bbox("all"))

    def _on_list_canvas_configure(self, event) -> None:
        self._list_canvas.itemconfig(self._list_window, width=event.width)

    def _on_list_mousewheel(self, event) -> None:
        self._list_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _scroll_to_top(self) -> None:
        self._list_canvas.yview_moveto(0)

    def _clear_list(self) -> None:
        for widget in self.list_frame.winfo_children():
            widget.destroy()

    def _refresh_day_choices(self) -> None:
        year = self._validated_year()
        month = int(self.cutoff_month_var.get())
        days = [f"{d:02d}" for d in range(1, calendar.monthrange(year, month)[1] + 1)]
        current = self.cutoff_day_var.get()
        self.day_menu.configure(values=days)
        if current not in days:
            self.cutoff_day_var.set(days[-1])

    def _validated_year(self) -> int:
        current_year = datetime.now().year
        raw = self.cutoff_year_var.get().strip()
        if not raw.isdigit():
            self.cutoff_year_var.set(str(current_year))
            return current_year
        year = max(1900, min(2100, int(raw)))
        if str(year) != raw:
            self.cutoff_year_var.set(str(year))
        return year

    def _step_year(self, delta: int) -> None:
        year = max(1900, min(2100, self._validated_year() + delta))
        self.cutoff_year_var.set(str(year))
        self._refresh_day_choices()

    def _cutoff_datetime(self) -> datetime | None:
        if self.date_mode_var.get() == "不限日期":
            return None
        self._refresh_day_choices()
        return datetime(
            self._validated_year(),
            int(self.cutoff_month_var.get()),
            int(self.cutoff_day_var.get()),
        )

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1024 ** 3:
            return f"{size / 1024 ** 3:.2f} GB"
        if size >= 1024 ** 2:
            return f"{size / 1024 ** 2:.2f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"


def main() -> None:
    ctk.set_appearance_mode(load_app_settings().get("appearance", "light"))
    ctk.set_default_color_theme("blue")
    ctk.set_widget_scaling(1.06)
    root = ctk.CTk()
    ModernOrganizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
