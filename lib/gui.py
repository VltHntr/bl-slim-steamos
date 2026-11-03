import tkinter as tk


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("bl-slim-steamos")
        self.root.geometry("750x400")

    def run(self):
        self.root.mainloop()
