# Demo assets

| File | What it is |
| --- | --- |
| `demo.cast` | An [asciinema](https://asciinema.org) v2/v3 recording of the full `manifest → sign → verify (PASS) → verify (REJECTED)` loop. Play it locally with `asciinema play assets/demo.cast`. |
| `demo.tape` | A [vhs](https://github.com/charmbracelet/vhs) script that renders the same loop to an animated GIF. |

## Re-record the cast

```bash
go build -o skillprov .
cp -r testdata/clean-skill testdata/poisoned-skill /tmp/ssdemo/
cd /tmp/ssdemo
asciinema rec --overwrite -c ./run_demo.sh demo.cast
```

## Render the GIF

```bash
go build -o skillprov .
cp -r testdata/clean-skill testdata/poisoned-skill .
vhs assets/demo.tape   # writes assets/demo.gif
```

## Publish the cast (optional)

Upload `demo.cast` to asciinema.org and replace the `PLACEHOLDER` id in the
README badge with the returned recording id:

```bash
asciinema upload assets/demo.cast
```
