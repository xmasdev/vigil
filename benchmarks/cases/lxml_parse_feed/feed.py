from lxml import etree


def read_titles(path="feed.xml"):
    tree = etree.parse(path)
    return [t.text for t in tree.iter("title")]


if __name__ == "__main__":
    print(read_titles())
