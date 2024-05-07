def command_print_probes(probe_slice):
    """
    Call as `print_probes "<manager>.Probes"
    """
    slicev = eval(None, probe_slice).Variable
    for i in range(0, slicev.Len):
        probe = slicev.Value[i]
        name = probe.ProbeIdentificationPair.EBPFFuncName
        state = probe.state
        print("{}: {} => {}".format(i, name, state))
