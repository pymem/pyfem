import sys, os; sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import pyfem; from requests import get

offsets = get("https://offsets.ntgetwritewatch.workers.dev/offsets.json").json()
mem     = pyfem.PyFem("RobloxPlayerBeta.exe")

base    = mem.base_address

def getcamaddy():
    visEngine     = mem.pymem.read_longlong(
        base + int(offsets["VisualEnginePointer"], 16)
    )
    fakeDatamodel = mem.pymem.read_longlong(
        visEngine + int(offsets["VisualEngineToDataModel1"], 16)
    )
    dataModel     = mem.pymem.read_longlong(
        fakeDatamodel + int(offsets["VisualEngineToDataModel2"], 16)
    )
    wsAddr        = mem.pymem.read_longlong(
        dataModel + int(offsets["Workspace"], 16)
    )
    camAddr       = mem.pymem.read_longlong(
        wsAddr + int(offsets["Camera"], 16)
    )

    return camAddr


if __name__ == "__main__":
    while True:
        hum = mem.pymem.read_longlong(getcamaddy() + int(offsets['CameraSubject'], 16))
        mem.pymem.write_float(hum + int(offsets['WalkSpeedCheck'], 16), float('inf'))
        mem.pymem.write_float(hum + int(offsets['WalkSpeed'], 16), float(120))
