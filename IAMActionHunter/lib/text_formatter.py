from colorama import Fore, Style


class color:
    """
    Colorama color class
    Usage: print(color.red("This is red text"))
    Args: string (str): String to color
    """

    def red(string):
        return f"{Fore.RED}{string}{Style.RESET_ALL}"

    def green(string):
        return f"{Fore.GREEN}{string}{Style.RESET_ALL}"

    def yellow(string):
        return f"{Fore.YELLOW}{string}{Style.RESET_ALL}"
