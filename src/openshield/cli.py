import typer

from .exit_codes import INTERNAL_ERROR
from .collect import collect
from .models import PackageRef, Unresolvable
from .render import render_assessment, render_unresolvable
from .resolve import resolve_all
from .score import score

app = typer.Typer()


@app.command()
def check():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def intercept():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def enable():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def disable():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def status():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def doctor():
    raise typer.Exit(code=INTERNAL_ERROR)


@app.command()
def history():
    raise typer.Exit(code=INTERNAL_ERROR)

@app.command()
def check(specs: list[str] = typer.Argument(..., help="npm package specifiers")):
    """Analyze packages and print. Installs nothing, prompts for nothing."""
    results = resolve_all(specs)
    refs = [r for r in results if isinstance(r, PackageRef)]

    evidence = {e.package: e for e in collect(refs)}

    blocks = [
        render_unresolvable(r) if isinstance(r, Unresolvable)
        else render_assessment(score(evidence[r]))
        for r in results
    ]
    typer.echo("\n\n".join(blocks))