from __future__ import annotations
"""HTML Elements DOM Tree Explorer for CTF DevTools."""
import re
from typing import Optional, Dict, Any, List
from bs4 import BeautifulSoup, Tag, NavigableString
from textual.widgets import Tree
from textual.widgets._tree import TreeNode

def is_tag_hidden(tag: Tag) -> bool:
    """Determines if an HTML element is hidden visually in the DOM."""
    if tag.has_attr('hidden'):
        return True
    style = str(tag.get('style', '')).replace(' ', '').lower()
    if 'display:none' in style or 'visibility:hidden' in style or 'opacity:0' in style:
        return True
    if tag.name == 'input' and str(tag.get('type', '')).lower() == 'hidden':
        return True
    return False

def format_tag_label(tag: Tag, flag_tracker=None) -> str:
    """Builds a concise, informative label for a DOM Tree node."""
    parts = [f"<{tag.name}"]
    if tag.get('id'):
        parts.append(f"#{tag['id']}")
    if tag.get('class'):
        cls = tag['class']
        cls_str = '.'.join(cls) if isinstance(cls, list) else cls
        parts.append(f".{cls_str[:25]}")
    if tag.name == 'input' and tag.get('type'):
        parts.append(f"[type={tag['type']}]")
    if tag.name == 'a' and tag.get('href'):
        href = str(tag['href'])[:30]
        parts.append(f"[href='{href}']")
    parts.append(">")

    badges = []
    if is_tag_hidden(tag):
        badges.append("🔒[HIDDEN]")
    
    # Check for suspicious attributes
    for attr, val in tag.attrs.items():
        val_str = ' '.join(val) if isinstance(val, list) else str(val)
        if any(w in attr.lower() or w in val_str.lower() for w in ['flag', 'secret', 'token', 'key', 'admin', 'auth', 'pass']):
            badges.append(f"🔑[{attr}]")
            break
            
    if flag_tracker:
        flags = flag_tracker.scan(str(tag.attrs))
        if flags:
            badges.append("🚩[FLAG]")

    suffix = f" {' '.join(badges)}" if badges else ""
    return f"{' '.join(parts)}{suffix}"

def build_dom_tree(
    tree: Tree,
    html: str,
    search_query: str = "",
    hidden_only: bool = False,
    flag_tracker = None
):
    """Parses HTML and builds a recursive, expandable tree in Textual."""
    tree.clear()
    if not html or not html.strip():
        tree.root.set_label("Document (Empty HTML)")
        return

    soup = BeautifulSoup(html, 'html.parser')
    tree.root.set_label("Document (<!DOCTYPE html>)")
    tree.root.expand()

    query_lower = search_query.strip().lower() if search_query else ""

    def matches_filter(tag: Tag) -> bool:
        if hidden_only and not is_tag_hidden(tag):
            # Check if any descendant is hidden
            has_hidden_child = any(is_tag_hidden(desc) for desc in tag.find_all(True))
            if not has_hidden_child:
                return False
        if query_lower:
            # Match tag name, id, class, attributes, or direct text
            if query_lower in tag.name.lower():
                return True
            for k, v in tag.attrs.items():
                v_str = ' '.join(v) if isinstance(v, list) else str(v)
                if query_lower in k.lower() or query_lower in v_str.lower():
                    return True
            txt = tag.get_text()
            if query_lower in txt.lower():
                return True
            # Or if any descendant matches
            return False
        return True

    def add_node_recursive(parent_tag: Tag, parent_tree_node: TreeNode, depth: int = 0):
        if depth > 18:
            return
        for child in parent_tag.children:
            if isinstance(child, Tag):
                if not matches_filter(child):
                    continue
                label = format_tag_label(child, flag_tracker)
                should_expand = depth < 2 or is_tag_hidden(child) or bool(query_lower)
                child_branch = parent_tree_node.add(label, data=child, expand=should_expand)
                add_node_recursive(child, child_branch, depth + 1)
            elif isinstance(child, NavigableString):
                txt = child.strip()
                if txt and len(txt) > 0:
                    if query_lower and query_lower not in txt.lower():
                        continue
                    clean_txt = txt.replace('\n', ' ')
                    snippet = (clean_txt[:45] + '...') if len(clean_txt) > 45 else clean_txt
                    parent_tree_node.add_leaf(f'"{snippet}"', data=txt)

    # Walk from top elements: <html> or children of soup
    html_tag = soup.find('html')
    if html_tag:
        label = format_tag_label(html_tag, flag_tracker)
        html_branch = tree.root.add(label, data=html_tag, expand=True)
        add_node_recursive(html_tag, html_branch, depth=1)
    else:
        add_node_recursive(soup, tree.root, depth=0)

def format_tag_details(tag: Tag) -> str:
    """Generates a clean metadata summary of the selected element's attributes and flags."""
    lines = [f"=== TAG: <{tag.name.upper()}> ==="]
    
    # Check hidden status
    if is_tag_hidden(tag):
        lines.append("🔒 VISIBILITY: HIDDEN (Invisible in normal browser rendering!)")
    else:
        lines.append("👁  VISIBILITY: Visible in normal rendering")

    lines.append("\n[Attributes]:")
    if tag.attrs:
        for k, v in tag.attrs.items():
            if isinstance(v, list):
                val_str = ' '.join(v)
            else:
                val_str = str(v)
            lines.append(f"  • {k} = '{val_str}'")
    else:
        lines.append("  (No attributes defined)")

    # Direct text content
    direct_text = tag.find(text=True, recursive=False)
    if direct_text and direct_text.strip():
        lines.append(f"\n[Direct Text]: {direct_text.strip()[:150]}")

    return "\n".join(lines)
