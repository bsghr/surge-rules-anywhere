
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert Loyalsoldier Surge RULE-SET to Anywhere ARR format.
"""

import ipaddress
import logging
import re
import sys
from pathlib import Path
from urllib.parse import quote

import requests
import yaml


BASE_URL = (
    "https://raw.githubusercontent.com/"
    "Loyalsoldier/surge-rules/release/"
)

CONFIG_FILE = Path("rules.yml")
OUTPUT_DIR = Path("rules")
MAX_RULES = 100_000
TIMEOUT = 30

TYPE_MAP = {
    "DOMAIN": 2,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN-KEYWORD": 3,
    "IP-CIDR": 0,
    "IP-CIDR6": 1,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("converter")


def create_session():
    """创建带重试机制的 HTTP 会话。"""
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()

    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)

    return session


def load_config():
    """读取规则配置文件。"""
    if not CONFIG_FILE.exists():
        raise FileNotFoundError("未找到 rules.yml")

    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError("rules.yml 格式错误")

    rules = config.get("rules")

    if not isinstance(rules, list) or not rules:
        raise ValueError("rules.yml 中没有有效的 rules 配置")

    for item in rules:
        if not isinstance(item, dict):
            raise ValueError("规则配置项格式错误")

        if not item.get("name") or not item.get("source"):
            raise ValueError("每个规则必须配置 name 和 source")

        source = Path(str(item["source"]))

        if (
            source.is_absolute()
            or ".." in source.parts
            or source.parts[0] != "ruleset"
        ):
            raise ValueError(
                f"不允许的规则来源路径：{item['source']}"
            )

    return rules


def download_rules(session, source):
    """下载上游 RULE-SET 文件。"""
    url = BASE_URL + quote(source, safe="/")

    logger.info("正在下载：%s", url)

    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()

    content = response.content.decode("utf-8-sig")

    if not content.strip():
        raise ValueError(f"上游规则文件为空：{source}")

    return content


def normalize_domain(value):
    """规范化域名并进行基本格式检查。"""
    value = value.strip().lower().rstrip(".")

    if not value or any(c.isspace() for c in value):
        return None

    if any(c in value for c in "/,:"):
        return None

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(value) > 253:
        return None

    labels = value.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
        ):
            return None

    return value


def convert_line(line):
    """
    将一条 Surge 规则转换为 Anywhere 规则。

    返回：
        (type_id, value)
        或 None（不支持或无效）
    """
    line = line.strip()

    if not line or line.startswith(("#", "//")):
        return None

    parts = [part.strip() for part in line.split(",")]

    if len(parts) < 2:
        return None

    rule_type = parts[0].upper()
    value = parts[1]

    if rule_type not in TYPE_MAP:
        return None

    type_id = TYPE_MAP[rule_type]

    if type_id in (0, 1):
        try:
            network = ipaddress.ip_network(
                value,
                strict=False,
            )
        except ValueError:
            return None

        if type_id == 0 and network.version != 4:
            return None

        if type_id == 1 and network.version != 6:
            return None

        value = str(network)

    else:
        value = normalize_domain(value)

        if value is None:
            return None

    return type_id, value


def parse_rules(content):
    """解析规则并去重，保留首次出现的规则。"""
    rules = []
    seen = set()

    stats = {
        "total": 0,
        "supported": 0,
        "unsupported": 0,
        "invalid": 0,
        "duplicate": 0,
    }

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "//")):
            continue

        stats["total"] += 1

        parts = [part.strip() for part in line.split(",")]

        if not parts or parts[0].upper() not in TYPE_MAP:
            stats["unsupported"] += 1
            continue

        result = convert_line(line)

        if result is None:
            stats["invalid"] += 1
            continue

        if result in seen:
            stats["duplicate"] += 1
            continue

        seen.add(result)
        rules.append(result)
        stats["supported"] += 1

    return rules, stats


def safe_filename(name):
    """生成安全的文件名。"""
    filename = re.sub(
        r"[^a-zA-Z0-9_-]+",
        "-",
        name.strip(),
    ).strip("-")

    if not filename:
        raise ValueError(f"无效的规则集名称：{name}")

    return filename


def write_rule_files(name, source, rules):
    """按 Anywhere 的 100000 条限制拆分并写入 ARR 文件。"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    filename = safe_filename(name)

    chunks = [
        rules[i:i + MAX_RULES]
        for i in range(0, len(rules), MAX_RULES)
    ]

    if not chunks:
        raise ValueError(f"{name} 没有可输出的规则")

    generated_files = []

    for index, chunk in enumerate(chunks, start=1):

        if len(chunks) == 1:
            output_name = filename
            display_name = name
        else:
            output_name = f"{filename}-{index}"
            display_name = f"{name}-{index}"

        output_path = OUTPUT_DIR / f"{output_name}.arrs"

        lines = [
            f"name = {display_name}",
            f"# Source: {source}",
            f"# Rules: {len(chunk)}",
            "",
        ]

        lines.extend(
            f"{type_id}, {value}"
            for type_id, value in chunk
        )

        content = "\n".join(lines) + "\n"

        temp_path = output_path.with_suffix(".arrs.tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(output_path)

        generated_files.append(output_path)

        logger.info(
            "已生成：%s（%s 条规则）",
            output_path,
            len(chunk),
        )

    # 删除该规则集之前生成的多余分片。
    current_names = {path.name for path in generated_files}

    for old_file in OUTPUT_DIR.glob(f"{filename}*.arrs"):
        if old_file.name not in current_names:
            old_file.unlink()
            logger.info("已删除旧文件：%s", old_file)

    return generated_files


def main():
    logger.info("开始转换 Loyalsoldier RULE-SET")

    rules_config = load_config()
    session = create_session()

    total_rules = 0
    total_files = 0
    failed = []

    for item in rules_config:
        name = str(item["name"]).strip()
        source = str(item["source"]).strip()

        logger.info("=" * 50)
        logger.info("处理规则集：%s", name)

        try:
            content = download_rules(session, source)

            rules, stats = parse_rules(content)

            if not rules:
                raise ValueError(
                    "未解析到有效规则，停止生成以避免空文件覆盖"
                )

            files = write_rule_files(
                name,
                source,
                rules,
            )

            total_rules += len(rules)
            total_files += len(files)

            logger.info(
                "统计：原始规则 %d，成功 %d，"
                "不支持 %d，无效 %d，重复 %d",
                stats["total"],
                stats["supported"],
                stats["unsupported"],
                stats["invalid"],
                stats["duplicate"],
            )

        except Exception as exc:
            failed.append(name)
            logger.exception(
                "规则集 %s 处理失败：%s",
                name,
                exc,
            )

    logger.info("=" * 50)
    logger.info("转换任务结束")
    logger.info("成功生成文件：%d", total_files)
    logger.info("有效规则总数：%d", total_rules)
    logger.info("失败规则集：%d", len(failed))

    if failed:
        logger.error("失败列表：%s", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
