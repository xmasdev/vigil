from vigil import osv, symbols


def test_symbols_named_in_advisory_are_a_recall_floor():
    adv = osv.Advisory("GHSA-x", [], "pyyaml", "5.3.1", "Improper Input Validation",
                       "arbitrary code execution through the full_load method or with the FullLoader loader.", None, [])
    cands = ["yaml.full_load", "yaml.loader.FullLoader", "yaml.load", "yaml.loader.Loader", "yaml.safe_load"]
    got = [s.qualname for s in symbols.named_in_advisory(adv, cands, chosen={"yaml.full_load"})]
    # FullLoader is named and was dropped by the model -> restored; generic names (load, Loader) are not added
    assert got == ["yaml.loader.FullLoader"]
