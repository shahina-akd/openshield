import typer

from .exit_codes import INTERNAL_ERROR
from .collect import collect
from .models import PackageRef, Unresolvable
from .render import render_assessment, render_unresolvable
from .resolve import resolve_all
from .score import score
from .run import run_intercept

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


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def intercept(ctx: typer.Context):
    """The full loop: analyze, prompt, run or refuse. Invoked by the M2 shim."""
    raise typer.Exit(code=run_intercept(ctx.args))

@app.command()
def config(
    init: bool = typer.Option(False, "--init", help="write a template"),
    path: bool = typer.Option(False, "--path", help="print the file location"),
):
    """Show effective settings and where each came from."""
    # Imported INSIDE the function on purpose: this command is also named
    # `config`, so a module-level `from . import config` would be shadowed by
    # it and every reference here would hit the function instead.
    from . import config as config_module

    if path:
        typer.echo(config_module.config_path())
        return
    if init:
        created = config_module.ensure_file()
        typer.echo(("wrote " if created else "already exists: ")
                   + str(config_module.config_path()))
        return

    for key, info in config_module.effective().items():
        typer.echo(f"{key:24} {str(info['value']):14} ({info['source']})")