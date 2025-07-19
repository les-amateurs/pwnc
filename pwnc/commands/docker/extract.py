from ...util import *
from tempfile import TemporaryDirectory
import json


def command(args: Args):
    """
    Extracting properly without running the image is ... annoying.
    `docker save` generates a tarfile with all the layers, but you still need
    to sort through all the layers to find the right files. Then you need to deal
    with the fact that layers might overwrite each others files as well.
    """

    with TemporaryDirectory() as tmp:
        tmp = Path(tmp).absolute()
        tarfile = tmp / "image.tar"
        run(
            ["docker", "save", args.image, "-o", tarfile.name],
            shell=False,
            capture_output=True,
            cwd=tmp,
        )
        run(["tar", "-xf", tarfile.name], shell=False, capture_output=True, cwd=tmp)

        with open(tmp / "manifest.json") as fp:
            manifest = json.load(fp)[0]

        layerPaths = manifest["Layers"]
        layerPaths = map(lambda p: tmp / p, layerPaths)
        layerPaths: list[Path] = list(layerPaths)

        layers: list[set[Path]] = []
        for layer in layerPaths:
            proc = run(["tar", "-t", "-f", str(layer)], shell=False, capture_output=True)
            files = proc.stdout.splitlines()
            wanted = filter(lambda f: f.endswith(args.file), files)
            relative = set()
            for file in wanted:
                file = Path(file)
                if file.is_relative_to("/"):
                    relative.add(file.relative_to("/"))
                else:
                    relative.add(file)
            layers.append(relative)

        dump = Path(args.image)
        dump.mkdir(exist_ok=True)

        current: set[Path] = set()
        for i, layer in enumerate(layers):
            extractions = layer.difference(current)
            current.update(layer)
            for file in extractions:
                dst = dump / file
                src = layerPaths[i].parent / file
                run(
                    ["tar", "-xf", str(layerPaths[i]), str(file)],
                    shell=False,
                    capture_output=True,
                    cwd=layerPaths[i].parent,
                )

                if src.is_symlink():
                    # follow link more times?
                    # do we care about directory traversal?
                    real = Path(os.path.normpath((file.parent / src.readlink())))
                    if real in current:
                        continue
                    current.add(real)
                    src = layerPaths[i].parent / real

                dst.parent.mkdir(exist_ok=True, parents=True)
                shutil.copy(src, dst)
                err.info(f"extracted {str(file)!r} to {str(dst)!r}")

        if len(current) == 0:
            err.warn("failed to extract any files")
