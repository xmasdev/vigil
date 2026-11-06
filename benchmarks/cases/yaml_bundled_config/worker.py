from settings import load_settings


def main():
    settings = load_settings()
    print("polling every", settings["interval"], "seconds")


if __name__ == "__main__":
    main()
