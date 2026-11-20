def test_whitelist_url_is_not_replaced():
    assert not res["is_modified"]
    assert res["safe_text"] == text


def test_fake_brand_url_is_replaced():
    text = "Куттуктайбыз! Сиз iPhone 15 уттуңуз: https://my-beeline.kg.example"
    assert res["is_modified"]
    rep = res["replaced_urls"][0]
    assert rep["brand"] == "Beeline"



    reg = SafeLinksRegistry()
