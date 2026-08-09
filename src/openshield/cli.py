import typer

from .exit_codes import INTERNAL_ERROR

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
