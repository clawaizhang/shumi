"""
CLI工具 - 礼部负责
命令行交互界面
"""

import sys
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shumi.core.detector import SensitiveInfoDetector
from shumi.core.encryptor import LocalEncryptor, LocalDecryptor
from shumi.core.placeholder import PlaceholderManager, is_placeholder
from shumi.core.auditor import SecurityAuditor

console = Console()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 默认配置路径
DEFAULT_CONFIG_DIR = Path.home() / '.openclaw' / 'security'
DEFAULT_PUBLIC_KEY = DEFAULT_CONFIG_DIR / 'id_rsa.pub'


@click.group()
@click.version_option(version='0.1.0', prog_name='ai-security')
@click.option('--verbose', '-v', is_flag=True, help='启用详细输出')
@click.pass_context
def cli(ctx, verbose):
    """AI安全审计工具 - 保护您的敏感信息"""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@cli.group()
def config():
    """配置管理"""
    pass


@config.command('init')
@click.option('--public-key', '-k', type=click.Path(), 
              help='SSH公钥文件路径')
def init_config(public_key):
    """初始化配置"""
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # 检查公钥
    if public_key:
        key_path = Path(public_key)
        if not key_path.exists():
            console.print(f"[red]错误: 公钥文件不存在: {public_key}[/red]")
            sys.exit(1)
    else:
        # 尝试自动发现
        ssh_dir = Path.home() / '.ssh'
        key_candidates = [
            ssh_dir / 'id_rsa.pub',
            ssh_dir / 'id_ed25519.pub',
        ]
        key_path = None
        for candidate in key_candidates:
            if candidate.exists():
                key_path = candidate
                break
    
    if key_path:
        # 复制公钥到配置目录
        import shutil
        dest = DEFAULT_CONFIG_DIR / 'id_rsa.pub'
        shutil.copy2(key_path, dest)
        console.print(f"[green]✓[/green] 已配置公钥: {key_path}")
    else:
        console.print("[yellow]⚠[/yellow] 未找到SSH公钥，请使用 'ai-security config set-public-key' 设置")
    
    console.print(f"[green]✓[/green] 配置目录: {DEFAULT_CONFIG_DIR}")
    console.print("\n[bold]下一步:[/bold]")
    console.print("1. 在 ~/.openclaw/config.yaml 中添加:")
    console.print("   preprocessors:")
    console.print("     - shumi.plugins.openclaw_hook:SecurityAuditHook")


@config.command('set-public-key')
@click.argument('key_path', type=click.Path(exists=True))
def set_public_key(key_path):
    """设置加密公钥"""
    import shutil
    
    src = Path(key_path)
    dest = DEFAULT_CONFIG_DIR / 'id_rsa.pub'
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    shutil.copy2(src, dest)
    dest.chmod(0o644)
    
    console.print(f"[green]✓[/green] 公钥已设置: {dest}")
    
    # 显示密钥指纹
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_content = dest.read_text()
        if key_content.startswith('ssh-rsa'):
            key = serialization.load_ssh_public_key(
                key_content.encode(),
                backend=default_backend()
            )
        else:
            key = serialization.load_pem_public_key(
                key_content.encode(),
                backend=default_backend()
            )
        
        from shumi.core.encryptor import LocalEncryptor
        encryptor = LocalEncryptor(dest)
        fingerprint = encryptor.get_key_fingerprint()
        console.print(f"[blue]ℹ[/blue] 密钥指纹: {fingerprint}")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] 无法读取密钥指纹: {e}")


@config.command('show')
def show_config():
    """显示当前配置"""
    console.print(Panel("[bold]AI安全审计配置[/bold]"))
    
    table = Table(show_header=False)
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="green")
    
    # 配置目录
    table.add_row("配置目录", str(DEFAULT_CONFIG_DIR))
    table.add_row("配置目录存在", "是" if DEFAULT_CONFIG_DIR.exists() else "否")
    
    # 公钥
    pub_key = DEFAULT_CONFIG_DIR / 'id_rsa.pub'
    if pub_key.exists():
        table.add_row("公钥", str(pub_key))
        try:
            encryptor = LocalEncryptor(pub_key)
            table.add_row("密钥指纹", encryptor.get_key_fingerprint() or "未知")
        except Exception as e:
            table.add_row("密钥状态", f"[red]错误: {e}[/red]")
    else:
        table.add_row("公钥", "[yellow]未配置[/yellow]")
    
    console.print(table)


@cli.command('scan')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--fix', is_flag=True, help='自动脱敏并保存到新文件')
@click.option('--output', '-o', type=click.Path(), help='输出文件路径')
def scan_file(file_path, fix, output):
    """扫描文件中的敏感信息"""
    detector = SensitiveInfoDetector()
    matches = detector.scan_file(file_path)
    
    if not matches:
        console.print("[green]✓[/green] 未发现敏感信息")
        return
    
    console.print(f"[yellow]发现 {len(matches)} 处敏感信息:[/yellow]\n")
    
    table = Table()
    table.add_column("类型", style="cyan")
    table.add_column("内容片段", style="yellow")
    table.add_column("位置", style="blue")
    table.add_column("置信度", style="green")
    
    for match in matches:
        masked = match.matched_text[:8] + "****" if len(match.matched_text) > 8 else "****"
        table.add_row(
            match.match_type,
            masked,
            f"{match.start_pos}-{match.end_pos}",
            f"{match.confidence:.2%}"
        )
    
    console.print(table)
    
    if fix:
        if not output:
            output = str(Path(file_path).with_suffix('.sanitized' + Path(file_path).suffix))
        
        # 需要公钥才能脱敏
        pub_key = DEFAULT_CONFIG_DIR / 'id_rsa.pub'
        if not pub_key.exists():
            console.print("[red]错误: 未配置公钥，无法脱敏[/red]")
            console.print("请先运行: ai-security config set-public-key <path>")
            sys.exit(1)
        
        # 处理脱敏
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        encryptor = LocalEncryptor(pub_key)
        placeholder_manager = PlaceholderManager()
        
        processed = content
        for match in sorted(matches, key=lambda m: m.start_pos, reverse=True):
            try:
                encrypted = encryptor.encrypt(match.matched_text)
                placeholder = placeholder_manager.create_placeholder(
                    encrypted, match.match_type
                )
                processed = (
                    processed[:match.start_pos] +
                    placeholder +
                    processed[match.end_pos:]
                )
            except Exception as e:
                logger.error(f"Failed to process match: {e}")
        
        with open(output, 'w', encoding='utf-8') as f:
            f.write(processed)
        
        console.print(f"\n[green]✓[/green] 脱敏文件已保存: {output}")


@cli.command('decrypt')
@click.argument('placeholder', required=False)
@click.option('--private-key', '-k', type=click.Path(exists=True),
              help='RSA私钥文件路径')
@click.option('--file', '-f', type=click.Path(exists=True),
              help='从文件中读取占位符')
@click.option('--interactive', '-i', is_flag=True, help='交互式解密')
def decrypt_command(placeholder, private_key, file, interactive):
    """解密占位符获取原始值"""
    
    # 获取私钥路径
    if not private_key:
        ssh_dir = Path.home() / '.ssh'
        key_candidates = [
            ssh_dir / 'id_rsa',
            ssh_dir / 'id_ed25519',
        ]
        for candidate in key_candidates:
            if candidate.exists():
                private_key = str(candidate)
                break
    
    if not private_key:
        console.print("[red]错误: 未找到私钥，请使用 -k 指定[/red]")
        sys.exit(1)
    
    # 获取待解密的占位符列表
    placeholders = []
    
    if file:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
        pm = PlaceholderManager()
        placeholders = pm.extract_placeholders_from_text(content)
    elif placeholder:
        placeholders = [placeholder]
    elif interactive:
        console.print("[bold]交互式解密[/bold]")
        console.print("请输入占位符（每行一个，输入空行结束）:")
        while True:
            p = click.prompt("", default="", show_default=False)
            if not p:
                break
            placeholders.append(p)
    else:
        console.print("[red]错误: 请提供占位符或使用 --file/--interactive 选项[/red]")
        sys.exit(1)
    
    if not placeholders:
        console.print("[yellow]没有需要解密的占位符[/yellow]")
        return
    
    # 解密
    pm = PlaceholderManager()
    decryptor = LocalDecryptor(private_key)
    
    results = []
    for ph in placeholders:
        if not is_placeholder(ph):
            results.append((ph, None, "无效的占位符格式"))
            continue
        
        try:
            encrypted_blob = pm.resolve_placeholder(ph)
            if not encrypted_blob:
                results.append((ph, None, "未找到占位符映射"))
                continue
            
            plaintext = decryptor.decrypt(encrypted_blob)
            results.append((ph, plaintext, None))
        except Exception as e:
            results.append((ph, None, str(e)))
    
    # 显示结果
    console.print("\n[bold]解密结果:[/bold]\n")
    
    for ph, plaintext, error in results:
        if error:
            console.print(f"[red]✗[/red] {ph}")
            console.print(f"    错误: {error}")
        else:
            console.print(f"[green]✓[/green] {ph}")
            # 脱敏显示
            if len(plaintext) > 20:
                display = plaintext[:10] + "..." + plaintext[-5:]
            else:
                display = plaintext
            console.print(f"    值: {display}")


@cli.group()
def audit():
    """审计日志管理"""
    pass


@audit.command('logs')
@click.option('--type', 'event_type', help='事件类型过滤')
@click.option('--placeholder', help='占位符过滤')
@click.option('--limit', '-n', default=50, help='显示条数')
def show_logs(event_type, placeholder, limit):
    """查看审计日志"""
    auditor = SecurityAuditor()
    logs = auditor.get_logs(
        event_type=event_type,
        placeholder=placeholder,
        limit=limit
    )
    
    if not logs:
        console.print("[yellow]没有符合条件的日志[/yellow]")
        return
    
    table = Table()
    table.add_column("时间", style="blue")
    table.add_column("类型", style="cyan")
    table.add_column("占位符", style="yellow")
    table.add_column("执行者", style="green")
    table.add_column("状态", style="red")
    
    for log in logs:
        status = "✓" if log.get('success') else "✗"
        table.add_row(
            log.get('timestamp', 'N/A')[:19],
            log.get('event_type', 'N/A'),
            log.get('placeholder', '-')[:30] + "..." if log.get('placeholder') and len(log.get('placeholder')) > 30 else log.get('placeholder', '-'),
            log.get('actor', 'N/A'),
            status
        )
    
    console.print(table)


@audit.command('stats')
def audit_stats():
    """查看审计统计"""
    auditor = SecurityAuditor()
    stats = auditor.get_stats()
    
    console.print(Panel("[bold]审计统计[/bold]"))
    
    table = Table(show_header=False)
    table.add_column("指标", style="cyan")
    table.add_column("值", style="green")
    
    table.add_row("总事件数", str(stats.get('total_events', 0)))
    table.add_row("唯一占位符数", str(stats.get('unique_placeholders', 0)))
    table.add_row("日志大小", f"{stats.get('log_file_size', 0) / 1024:.1f} KB")
    table.add_row("日志路径", stats.get('log_file_path', 'N/A'))
    
    console.print(table)
    
    # 事件类型分布
    if stats.get('events_by_type'):
        console.print("\n[bold]事件类型分布:[/bold]")
        type_table = Table()
        type_table.add_column("类型", style="cyan")
        type_table.add_column("数量", style="green")
        
        for event_type, count in sorted(stats['events_by_type'].items()):
            type_table.add_row(event_type, str(count))
        
        console.print(type_table)


@audit.command('verify')
def verify_integrity():
    """验证日志完整性"""
    auditor = SecurityAuditor()
    
    with console.status("[bold green]正在验证日志完整性..."):
        is_valid = auditor.verify_integrity()
    
    if is_valid:
        console.print("[green]✓[/green] 日志完整性验证通过")
    else:
        console.print("[red]✗[/red] 日志完整性验证失败")
        sys.exit(1)


@cli.command('status')
def show_status():
    """显示插件状态"""
    from shumi.plugins.openclaw_hook import SecurityAuditHook
    
    hook = SecurityAuditHook()
    health = hook.health_check()
    
    console.print(Panel("[bold]AI安全审计插件状态[/bold]"))
    
    if health['healthy']:
        console.print("[green]✓[/green] 插件状态: 健康")
    else:
        console.print("[red]✗[/red] 插件状态: 异常")
    
    table = Table()
    table.add_column("组件", style="cyan")
    table.add_column("状态", style="green")
    
    for component, status in health['checks'].items():
        status_str = "[green]✓[/green] 正常" if status else "[red]✗[/red] 异常"
        table.add_row(component, status_str)
    
    console.print(table)
    console.print(f"\n[blue]ℹ[/blue] {health['message']}")


if __name__ == '__main__':
    cli()
