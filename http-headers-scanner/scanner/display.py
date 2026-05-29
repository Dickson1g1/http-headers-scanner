from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from .grader import Finding, STATUS_OK, STATUS_WEAK, STATUS_MISSING

console = Console()

STATUS_STYLE = {
    STATUS_OK:      ("bold green",  "✔ ok     "),
    STATUS_WEAK:    ("bold yellow", "⚠ weak   "),
    STATUS_MISSING: ("bold red",    "✘ missing"),
}

GRADE_STYLE = {
    "A": "bold green",
    "B": "bold green",
    "C": "bold yellow",
    "D": "bold yellow",
    "F": "bold red",
}


def render(url: str, final_url: str, findings: list[Finding],
           numeric: int, grade: str) -> None:
    console.print()
    if url != final_url:
        console.print(f"[dim]Redirected →[/dim] [bold]{final_url}[/bold]\n")

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold", padding=(0, 1))
    table.add_column("Header",     min_width=30)
    table.add_column("Status",     width=12)
    table.add_column("Finding",    style="dim")

    for f in findings:
        style, label = STATUS_STYLE[f.status]
        table.add_row(
            Text(f.rule.name, style="bold" if f.status != STATUS_OK else ""),
            Text(label, style=style),
            f.reason,
        )

    console.print(table)

    grade_color = GRADE_STYLE.get(grade, "white")
    grade_text  = Text.assemble(
        ("  Score: ", "dim"),
        (f"{numeric}/100", "bold"),
        ("   Grade: ", "dim"),
        (grade, grade_color),
        ("  ", ""),
    )
    console.print(Panel(grade_text, expand=False, border_style="dim"))

    non_ok = [f for f in findings if f.status != STATUS_OK]
    if non_ok:
        console.print("\n[bold]Recommendations[/bold]")
        for f in non_ok:
            icon = "[yellow]⚠[/yellow]" if f.status == STATUS_WEAK else "[red]✘[/red]"
            console.print(f"  {icon}  [bold]{f.rule.name}[/bold]")
            console.print(f"     [dim]{f.rule.recommendation}[/dim]")
    console.print()
