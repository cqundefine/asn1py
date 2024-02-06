#!/usr/bin/env python3

import asn1
import der
import tkinter as tk
from tkinter import ttk
import sys
import oids
from dataclasses import dataclass
import datetime

# def display(node: asn1.Node, tree: ttk.Treeview, parent: str = ''):
#     if isinstance(node, asn1.Invalid):
#         tree.insert(parent, tk.END, text="INVALID")
#     elif isinstance(node, asn1.Boolean):
#         tree.insert(parent, tk.END, text=f"BOOLEAN  {str(node.value).lower()}")
#     elif isinstance(node, asn1.Integer):
#         tree.insert(parent, tk.END, text=f"INTEGER  {node.value}")
#     elif isinstance(node, asn1.Null):
#         tree.insert(parent, tk.END, text="NULL")
#     elif isinstance(node, asn1.ObjectIdentifier):
#         tree.insert(parent, tk.END, text=f"OBJECT IDENTIFIER  {node}  {oid.commonOIDs.get(str(node), '')}")
#     elif isinstance(node, asn1.Sequence):
#         item = tree.insert(parent, tk.END, text="SEQUENCE")
#         for child in node.children:
#             display(child, tree, item)
#     elif isinstance(node, asn1.Set):
#         item = tree.insert(parent, tk.END, text="SET")
#         for child in node.children:
#             display(child, tree, item)
#     elif isinstance(node, asn1.PrintableString):
#         tree.insert(parent, tk.END, text=f"PRINTABLE STRING  {node.value}")
#     elif isinstance(node, asn1.UTCTime):
#         tree.insert(parent, tk.END, text=f"UTC TIME  {node.value}")
#     elif isinstance(node, asn1.ContextSpecific):
#         item = tree.insert(parent, tk.END, text=f"[{node.tag}]")
#         display(node.value, tree, item)
#     else:
#         print(f"{type(node)} is not implemented yet")
if __name__ == '__main__':
    program, *args = sys.argv
    if len(args) == 0:
        print(f"Usage: {program} <file.der>")
        exit(1)
    file_path, *args = args

    window = tk.Tk()
    window.title("DER Tool")
    window.geometry("800x600")

    window.rowconfigure(0, weight=1)
    window.columnconfigure(0, weight=1)

    # window.tk.call("source", "Azure-ttk-theme/azure.tcl")
    # window.tk.call("set_theme", "dark")

    tree = ttk.Treeview(window)
    tree["columns"] = ("key", "value")
    
    tree.column("#0", width=0, stretch=tk.NO)
    tree.column("key", anchor=tk.W)
    tree.column("value", anchor=tk.W)

    tree.heading("key", text="Data", anchor=tk.CENTER)
    tree.heading("value", text="Value", anchor=tk.CENTER)

    # Certificate
    certificate = der.parse_from_file(file_path)
    
    # -tbsCertificate
    tbsCertificate = certificate.children[0]

    # --[0]-version
    version = tbsCertificate.children[0].value.value

    # --serialNumber
    serialNumber = tbsCertificate.children[1].value
    
    # --validity
    validity = tbsCertificate.children[4]
    # ---notBefore
    notBefore = validity.children[0].value
    # ---notAfter
    notAfter = validity.children[1].value

    # --issuer
    issuerSequence = tbsCertificate.children[3]
    issuer = {}
    for rdn in issuerSequence.children:
        ava = rdn.children[0]
        oid = str(ava.children[0])
        value = ava.children[1].value
        if oid in oids.commonOIDs:
            oid = oids.commonOIDs[oid]
        else:
            print(f"Unknown OID: {oid}")
        issuer[oid] = value
    issuerStr = ", ".join([f"{key}: {value}" for key, value in issuer.items()])

    tree.insert("", tk.END, text="", values=("Version", version))
    tree.insert("", tk.END, text="", values=("Serial Number", serialNumber))
    tree.insert("", tk.END, text="", values=("Valid after", notBefore))
    tree.insert("", tk.END, text="", values=("Valid before", notAfter))
    issuerTree = tree.insert("", tk.END, text="", values=("Issuer", ""))
    for key, value in issuer.items():
        tree.insert(issuerTree, tk.END, text="", values=(key, value))

    tree.pack(fill=tk.BOTH, expand=True)

    moreInfo = tk.Frame(window)
    moreInfo.pack(fill=tk.BOTH, expand=True)
    
    info = tk.Label(moreInfo, text="More info")
    info.pack()

    # on tree select
    def on_tree_select(event):
        item = tree.selection()[0]
        itemText = tree.item(item, "text")
        itemValues = tree.item(item, "values")
        info.config(text=f"{itemText} {itemValues}")

    tree.bind("<<TreeviewSelect>>", on_tree_select)

    window.mainloop()
