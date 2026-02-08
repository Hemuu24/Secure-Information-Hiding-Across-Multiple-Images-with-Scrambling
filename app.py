"""
Secure Multi-Image Steganography - GUI Application
Symmetric encryption + LSB steganography across multiple carrier images.
All interaction via GUI; no terminal I/O. Key is system-generated and managed.
"""

import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from PIL import Image, ImageTk

from cryptography.fernet import InvalidToken
from crypto_utils import generate_key, encrypt_message, decrypt_message, key_to_file, key_from_file
from stego_utils import encode_into_images, decode_from_images


# Max size to display thumbnails
THUMB_SIZE = (160, 120)


class StegoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Multi-Image Steganography")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)

        # State
        self.current_key: bytes | None = None
        self.carrier_paths: list[str] = []
        self.stego_paths: list[str] = []
        self.last_output_dir: str | None = None

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # Notebook: Encode / Decode
        nb = ttk.Notebook(main)
        nb.pack(fill=tk.BOTH, expand=True)

        encode_frame = ttk.Frame(nb, padding=5)
        decode_frame = ttk.Frame(nb, padding=5)
        nb.add(encode_frame, text="  Encode  ")
        nb.add(decode_frame, text="  Decode  ")

        self._build_encode_tab(encode_frame)
        self._build_decode_tab(decode_frame)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_encode_tab(self, parent: ttk.Frame):
        # Carrier images section
        top_section = ttk.LabelFrame(parent, text="Carrier images", padding=5)
        top_section.pack(fill=tk.X)

        btn_frame = ttk.Frame(top_section)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Select carrier images…", command=self._encode_select_images).pack(side=tk.LEFT, padx=(0, 8))
        self.encode_images_label = ttk.Label(btn_frame, text="No images selected")
        self.encode_images_label.pack(side=tk.LEFT)

        # Canvas + scroll for image thumbnails (carrier images at top)
        canvas_frame = ttk.Frame(top_section)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        self.encode_canvas = tk.Canvas(canvas_frame, height=140, highlightthickness=0)
        scroll_x = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.encode_canvas.xview)
        self.encode_canvas.configure(xscrollcommand=scroll_x.set)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.encode_canvas.pack(fill=tk.BOTH, expand=True)
        self.encode_thumb_frame = ttk.Frame(self.encode_canvas)
        self.encode_canvas.create_window((0, 0), window=self.encode_thumb_frame, anchor=tk.NW)
        self.encode_thumb_frame.bind("<Configure>", lambda e: self.encode_canvas.configure(scrollregion=self.encode_canvas.bbox("all")))

        # Secret message
        msg_frame = ttk.LabelFrame(parent, text="Secret message", padding=5)
        msg_frame.pack(fill=tk.X, pady=(8, 0))
        self.secret_text = tk.Text(msg_frame, height=4, wrap=tk.WORD, font=("Segoe UI", 10))
        self.secret_text.pack(fill=tk.X)
        ttk.Button(msg_frame, text="Encode (encrypt + hide in images)", command=self._do_encode).pack(anchor=tk.W, pady=(5, 0))

        # Encrypted text display (below images as per requirement)
        enc_frame = ttk.LabelFrame(parent, text="Encrypted text (hidden in images)", padding=5)
        enc_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.encrypted_text = tk.Text(enc_frame, height=6, wrap=tk.WORD, font=("Consolas", 9), state=tk.DISABLED)
        self.encrypted_text.pack(fill=tk.BOTH, expand=True)
        enc_btns = ttk.Frame(enc_frame)
        enc_btns.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(enc_btns, text="Save key to file…", command=self._save_key).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(enc_btns, text="Save stego images to folder…", command=self._save_stego_images).pack(side=tk.LEFT)

    def _build_decode_tab(self, parent: ttk.Frame):
        # Stego images section
        top_section = ttk.LabelFrame(parent, text="Stego images", padding=5)
        top_section.pack(fill=tk.X)

        hint = ttk.Label(top_section, text="Use the _stego.png files (not the originals), in the same order as when you encoded.")
        hint.pack(anchor=tk.W)
        btn_frame = ttk.Frame(top_section)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Select stego images…", command=self._decode_select_images).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="Load key from file…", command=self._load_key).pack(side=tk.LEFT, padx=(0, 8))
        self.decode_images_label = ttk.Label(btn_frame, text="No images selected")
        self.decode_images_label.pack(side=tk.LEFT, padx=(8, 0))

        canvas_frame = ttk.Frame(top_section)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        self.decode_canvas = tk.Canvas(canvas_frame, height=140, highlightthickness=0)
        scroll_x = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.decode_canvas.xview)
        self.decode_canvas.configure(xscrollcommand=scroll_x.set)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.decode_canvas.pack(fill=tk.BOTH, expand=True)
        self.decode_thumb_frame = ttk.Frame(self.decode_canvas)
        self.decode_canvas.create_window((0, 0), window=self.decode_thumb_frame, anchor=tk.NW)
        self.decode_thumb_frame.bind("<Configure>", lambda e: self.decode_canvas.configure(scrollregion=self.decode_canvas.bbox("all")))

        ttk.Button(parent, text="Decode (extract + decrypt)", command=self._do_decode).pack(anchor=tk.W, pady=(8, 0))

        # Decrypted text (below images)
        dec_frame = ttk.LabelFrame(parent, text="Decrypted message", padding=5)
        dec_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.decrypted_text = tk.Text(dec_frame, height=8, wrap=tk.WORD, font=("Segoe UI", 10), state=tk.DISABLED)
        self.decrypted_text.pack(fill=tk.BOTH, expand=True)

    def _encode_select_images(self):
        paths = filedialog.askopenfilenames(
            title="Select carrier images",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if paths:
            self.carrier_paths = list(paths)
            self.encode_images_label.config(text=f"{len(self.carrier_paths)} image(s) selected")
            self._show_encode_thumbnails()

    def _decode_select_images(self):
        paths = filedialog.askopenfilenames(
            title="Select stego images (same order as encoding)",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")]
        )
        if paths:
            self.stego_paths = list(paths)
            self.decode_images_label.config(text=f"{len(self.stego_paths)} image(s) selected")
            self._show_decode_thumbnails()

    def _show_encode_thumbnails(self):
        for w in self.encode_thumb_frame.winfo_children():
            w.destroy()
        for path in self.carrier_paths:
            try:
                im = Image.open(path).convert("RGB")
                im.thumbnail(THUMB_SIZE, Image.Resampling.LANCZOS)
                ph = ImageTk.PhotoImage(im)
                lbl = ttk.Label(self.encode_thumb_frame, image=ph, text=Path(path).name, compound=tk.TOP)
                lbl.image = ph
                lbl.pack(side=tk.LEFT, padx=4, pady=4)
            except Exception:
                lbl = ttk.Label(self.encode_thumb_frame, text=Path(path).name + "\n(load error)")
                lbl.pack(side=tk.LEFT, padx=4, pady=4)

    def _show_decode_thumbnails(self):
        for w in self.decode_thumb_frame.winfo_children():
            w.destroy()
        for path in self.stego_paths:
            try:
                im = Image.open(path).convert("RGB")
                im.thumbnail(THUMB_SIZE, Image.Resampling.LANCZOS)
                ph = ImageTk.PhotoImage(im)
                lbl = ttk.Label(self.decode_thumb_frame, image=ph, text=Path(path).name, compound=tk.TOP)
                lbl.image = ph
                lbl.pack(side=tk.LEFT, padx=4, pady=4)
            except Exception:
                lbl = ttk.Label(self.decode_thumb_frame, text=Path(path).name + "\n(load error)")
                lbl.pack(side=tk.LEFT, padx=4, pady=4)

    def _do_encode(self):
        msg = self.secret_text.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Encode", "Please enter a secret message.")
            return
        if len(self.carrier_paths) < 2:
            messagebox.showwarning("Encode", "Please select at least two carrier images.")
            return
        try:
            self.current_key = generate_key()
            ciphertext = encrypt_message(msg, self.current_key)
            # Choose output dir: last used or ask
            out_dir = self.last_output_dir or filedialog.askdirectory(title="Choose folder to save stego images")
            if not out_dir:
                return
            self.last_output_dir = out_dir
            self.stego_paths = encode_into_images(self.carrier_paths, ciphertext, out_dir)
            # Display encrypted text (base64 for readability in UI)
            self.encrypted_text.config(state=tk.NORMAL)
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, base64.b64encode(ciphertext).decode("ascii"))
            self.encrypted_text.config(state=tk.DISABLED)
            # Refresh encode tab thumbnails to show stego images if we want; requirement says "carrier images at top"
            messagebox.showinfo("Encode", f"Encoding complete. {len(self.stego_paths)} stego image(s) saved.\nSave the key file to decode later.")
        except ValueError as e:
            messagebox.showerror("Encode", str(e))
        except Exception as e:
            messagebox.showerror("Encode", str(e))

    def _do_decode(self):
        if not self.stego_paths:
            messagebox.showwarning("Decode", "Please select stego images.")
            return
        if not self.current_key:
            messagebox.showwarning("Decode", "Please load the key file (same key used when encoding).")
            return
        try:
            payload = decode_from_images(self.stego_paths)
            if not payload:
                messagebox.showerror(
                    "Decode",
                    "No data extracted. Make sure you selected the _stego.png files (not the original carriers) in the same order as encoding."
                )
                return
            if len(payload) > 10 * 1024 * 1024:  # 10 MB
                messagebox.showerror(
                    "Decode",
                    "Extracted data is too large (wrong images or order?). Use the stego images in the same order as encoding."
                )
                return
            plaintext = decrypt_message(payload, self.current_key)
            self.decrypted_text.config(state=tk.NORMAL)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, plaintext)
            self.decrypted_text.config(state=tk.DISABLED)
        except InvalidToken:
            messagebox.showerror(
                "Decode",
                "Decryption failed (invalid or wrong key).\n\nCheck:\n"
                "• Load the same .key file you saved after encoding\n"
                "• Select the _stego.png images (not the original carrier images)\n"
                "• Select stego images in the same order as the carrier images"
            )
        except Exception as e:
            messagebox.showerror("Decode", f"Decoding failed.\n\nDetails: {e}")

    def _save_key(self):
        if not self.current_key:
            messagebox.showwarning("Save key", "No key available. Encode first, then save the key.")
            return
        path = filedialog.asksaveasfilename(
            title="Save key",
            defaultextension=".key",
            filetypes=[("Key file", "*.key"), ("All files", "*.*")]
        )
        if path:
            try:
                key_to_file(path, self.current_key)
                messagebox.showinfo("Save key", "Key saved. Keep it secure to decode later.")
            except Exception as e:
                messagebox.showerror("Save key", str(e))

    def _load_key(self):
        path = filedialog.askopenfilename(
            title="Load key",
            filetypes=[("Key file", "*.key"), ("All files", "*.*")]
        )
        if path:
            try:
                self.current_key = key_from_file(path)
                messagebox.showinfo("Load key", "Key loaded. Select stego images and click Decode.")
            except Exception as e:
                messagebox.showerror("Load key", str(e))

    def _save_stego_images(self):
        if not self.stego_paths:
            messagebox.showinfo("Save stego images", "Encode first to generate stego images; they are already saved to the folder you chose.")
            return
        messagebox.showinfo("Save stego images", f"Stego images were already saved to:\n{Path(self.stego_paths[0]).parent}")

    def _on_close(self):
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    app = StegoApp()
    app.run()


if __name__ == "__main__":
    main()
