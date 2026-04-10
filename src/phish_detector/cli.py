import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from pathlib import Path

from phish_detector.parser import parse_eml
from phish_detector.features import extract_features
from phish_detector.model import predict

app = typer.Typer()
console = Console()

DEFAULT_MODEL = Path("models/phish_detector.pkl")


@app.command()
def analyze(
    eml_path: Path = typer.Argument(..., help="Path to the .eml file to analyze"),
    model_path: Path = typer.Option(DEFAULT_MODEL, help="Path to the trained model"),
):
    if not eml_path.exists():
        console.print(f"[bold red]File not found: {eml_path}[/bold red]")
        raise typer.Exit()

    if not model_path.exists():
        console.print(f"[bold red]Model not found at {model_path}. Train the model first.[/bold red]")
        raise typer.Exit()

    # Step 1 - Parse
    console.print("[bold cyan]Parsing email...[/bold cyan]")
    parsed = parse_eml(eml_path)

    # Step 2 - Extract features
    console.print("[bold cyan]Extracting features...[/bold cyan]")
    features = extract_features(parsed)

    # Step 3 - Predict
    console.print("[bold cyan]Running classifier...[/bold cyan]")
    result = predict(features, model_path)

    # Step 4 - Display verdict
    verdict = result["verdict"]
    confidence = result["confidence"]
    color = "red" if verdict == "phishing" else "green"

    console.print(Panel(
        f"[bold {color}]{verdict.upper()}[/bold {color}]\n"
        f"Confidence: {confidence * 100:.1f}%",
        title="Verdict",
        border_style=color,
    ))

    # Step 5 - Feature table
    table = Table(title="Extracted features", box=box.ROUNDED)
    table.add_column("Feature", style="cyan")
    table.add_column("Value", style="white")

    for key, value in features.items():
        if key != "from_domain":
            table.add_row(key, str(value))

    console.print(table)


@app.command()
def train(
    data_path: Path = typer.Argument(..., help="Path to the CSV dataset"),
    model_path: Path = typer.Option(DEFAULT_MODEL, help="Where to save the trained model"),
):
    from phish_detector.model import train as train_model

    console.print("[bold cyan]Training model...[/bold cyan]")
    report = train_model(data_path, model_path)

    console.print("[bold green]Training complete.[/bold green]")
    console.print(f"Model saved to: {model_path}")

    table = Table(title="Classification report", box=box.ROUNDED)
    table.add_column("Class", style="cyan")
    table.add_column("Precision", style="white")
    table.add_column("Recall", style="white")
    table.add_column("F1", style="white")

    for label, metrics in report.items():
        if isinstance(metrics, dict):
            table.add_row(
                label,
                str(round(metrics["precision"], 3)),
                str(round(metrics["recall"], 3)),
                str(round(metrics["f1-score"], 3)),
            )

    console.print(table)


if __name__ == "__main__":
    app()