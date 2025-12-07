
#!/usr/bin/env python3
"""
generate_context.py - Generate comprehensive project context for LLMs

Features:
- Smart directory structure with tree view
- Intelligent file content extraction
- Token estimation for LLM context limits
- Git information extraction
- Configurable via command-line arguments
- .gitignore support
- Priority ordering (important files first)
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Set, Dict, List, Tuple
from collections import defaultdict

# ============================================================================
# CONFIGURATION
# ============================================================================

OUTPUT_FILE = 'directory_info.txt'
SEPARATOR = "\n" + "=" * 80 + "\n"
THIN_SEPARATOR = "\n" + "-" * 40 + "\n"

# Directories to always exclude
DIRS_TO_EXCLUDE = {
    '.git', 'venv', 'env', '.venv', '__pycache__', '.idea', '.vscode',
    'node_modules', '.mypy_cache', '.pytest_cache', '.tox', '.eggs',
    '*.egg-info', 'dist', 'build', '.cache', '.coverage', 'htmlcov',
    '.ipynb_checkpoints', '.terraform', '.serverless'
}

# Directories to summarize (show file count instead of contents)
DIRS_TO_SUMMARIZE = {
    'signals', 'unprocessed', 'data', 'datasets', 'logs', 'outputs',
    'checkpoints', 'models', 'weights', 'assets', 'static', 'migrations'
}

# File extensions to skip entirely (binary/media files)
EXTENSIONS_TO_SKIP = {
    # Audio
    '.flac', '.wav', '.mp3', '.ogg', '.m4a', '.aac', '.wma', '.aiff',
    # Video
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.webm', '.flv',
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.ico', '.webp', '.svg',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.zst',
    # Binaries
    '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.lib',
    # Data/Model files
    '.pkl', '.pickle', '.npy', '.npz', '.h5', '.hdf5',
    '.pt', '.pth', '.ckpt', '.safetensors', '.onnx', '.pb',
    # Database
    '.db', '.sqlite', '.sqlite3', '.mdb',
    # Other
    '.pyc', '.pyo', '.class', '.jar', '.war', '.woff', '.woff2', '.ttf', '.eot'
}

# Text file extensions to include with full content
TEXT_EXTENSIONS = {
    # Code
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.scala', '.r',
    '.lua', '.pl', '.pm', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
    # Config
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.config',
    '.env', '.env.example', '.env.local', '.properties',
    # Documentation
    '.md', '.rst', '.txt', '.adoc',
    # Web
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
    # Data
    '.xml', '.csv', '.sql',
    # Special
    '.gitignore', '.dockerignore', '.editorconfig', '.prettierrc', '.eslintrc'
}

# Priority files (shown first in output)
PRIORITY_FILES = {
    'README.md', 'readme.md', 'README.rst', 'README.txt', 'README',
    'pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt',
    'package.json', 'Cargo.toml', 'go.mod', 'Gemfile', 'pom.xml',
    'Makefile', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env.example', 'config.yaml', 'config.json', 'settings.py',
    'main.py', 'app.py', 'index.js', 'index.ts', 'main.go', 'main.rs'
}

# Limits
MAX_FILES_PER_DIR = 30
MAX_FILE_SIZE_FULL = 20_000  # 50KB - show full content
MAX_FILE_SIZE_PARTIAL = 200_000  # 200KB - show partial content
MAX_LINES_PREVIEW = 100
ESTIMATED_CHARS_PER_TOKEN = 4

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def estimate_tokens(text: str) -> int:
    """Rough token estimation for LLMs."""
    return len(text) // ESTIMATED_CHARS_PER_TOKEN

def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}" if unit != 'B' else f"{size_bytes}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"

def should_exclude_dir(dirname: str, exclude_set: Set[str]) -> bool:
    """Check if directory should be excluded (supports wildcards)."""
    if dirname in exclude_set:
        return True
    for pattern in exclude_set:
        if pattern.startswith('*') and dirname.endswith(pattern[1:]):
            return True
    return False

def get_gitignore_patterns(rootdir: str) -> Set[str]:
    """Parse .gitignore and return patterns to exclude."""
    gitignore_path = os.path.join(rootdir, '.gitignore')
    patterns = set()
    
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simplified pattern handling
                        patterns.add(line.rstrip('/'))
        except Exception:
            pass
    
    return patterns

# ============================================================================
# GIT INFORMATION
# ============================================================================

def get_git_info(rootdir: str) -> Optional[str]:
    """Extract useful git information."""
    try:
        # Check if it's a git repo
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=rootdir,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return None
        
        info_parts = []
        
        # Current branch
        branch = subprocess.run(
            ['git', 'branch', '--show-current'],
            cwd=rootdir,
            capture_output=True,
            text=True
        )
        if branch.returncode == 0 and branch.stdout.strip():
            info_parts.append(f"Branch: {branch.stdout.strip()}")
        
        # Last commit
        commit = subprocess.run(
            ['git', 'log', '-1', '--format=%h - %s (%cr)'],
            cwd=rootdir,
            capture_output=True,
            text=True
        )
        if commit.returncode == 0 and commit.stdout.strip():
            info_parts.append(f"Last commit: {commit.stdout.strip()}")
        
        # Status summary
        status = subprocess.run(
            ['git', 'status', '--porcelain'],
            cwd=rootdir,
            capture_output=True,
            text=True
        )
        if status.returncode == 0:
            lines = status.stdout.strip().split('\n') if status.stdout.strip() else []
            if lines:
                modified = sum(1 for l in lines if l.startswith(' M') or l.startswith('M '))
                added = sum(1 for l in lines if l.startswith('A ') or l.startswith('??'))
                deleted = sum(1 for l in lines if l.startswith(' D') or l.startswith('D '))
                parts = []
                if modified:
                    parts.append(f"{modified} modified")
                if added:
                    parts.append(f"{added} untracked/added")
                if deleted:
                    parts.append(f"{deleted} deleted")
                if parts:
                    info_parts.append(f"Status: {', '.join(parts)}")
            else:
                info_parts.append("Status: Clean working tree")
        
        return '\n'.join(info_parts) if info_parts else None
        
    except FileNotFoundError:
        return None
    except Exception:
        return None

# ============================================================================
# DIRECTORY STRUCTURE
# ============================================================================

def get_directory_structure(rootdir: str, exclude_dirs: Set[str], 
                           summarize_dirs: Set[str], gitignore_patterns: Set[str]) -> Tuple[str, Dict]:
    """
    Creates a tree representation of the folder structure.
    Returns the tree string and statistics.
    """
    lines = []
    stats = defaultdict(int)
    
    def _walk_dir(path: str, prefix: str = "", is_last: bool = True):
        basename = os.path.basename(path)
        
        # Determine connectors for tree view
        connector = "└── " if is_last else "├── "
        
        if path == rootdir:
            lines.append(f"{os.path.basename(rootdir)}/")
            new_prefix = ""
        else:
            lines.append(f"{prefix}{connector}{basename}/")
            new_prefix = prefix + ("    " if is_last else "│   ")
        
        try:
            entries = sorted(os.listdir(path))
        except PermissionError:
            lines.append(f"{new_prefix}[Permission Denied]")
            return
        
        # Separate directories and files
        dirs = []
        files = []
        
        for entry in entries:
            entry_path = os.path.join(path, entry)
            if os.path.isdir(entry_path):
                if not should_exclude_dir(entry, exclude_dirs) and entry not in gitignore_patterns:
                    dirs.append(entry)
            else:
                if entry not in {OUTPUT_FILE, os.path.basename(__file__)}:
                    if entry not in gitignore_patterns:
                        files.append(entry)
        
        # Check if this directory should be summarized
        if basename in summarize_dirs:
            ext_counts = defaultdict(int)
            total_size = 0
            
            for f in files:
                ext = os.path.splitext(f)[1].lower() or '(no ext)'
                ext_counts[ext] += 1
                try:
                    total_size += os.path.getsize(os.path.join(path, f))
                except:
                    pass
            
            if files:
                summary_parts = [f"{count}{ext}" for ext, count in 
                               sorted(ext_counts.items(), key=lambda x: -x[1])[:5]]
                lines.append(f"{new_prefix}📦 [{len(files)} files, {format_size(total_size)}]: {', '.join(summary_parts)}")
            
            stats['summarized_dirs'] += 1
            stats['summarized_files'] += len(files)
            return
        
        # Process files
        files_to_show = []
        skipped_by_ext = defaultdict(int)
        
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTENSIONS_TO_SKIP:
                skipped_by_ext[ext] += 1
                stats['skipped_files'] += 1
            else:
                files_to_show.append(f)
                stats['total_files'] += 1
        
        # Show files (with limit)
        total_entries = len(dirs) + len(files_to_show) + (1 if skipped_by_ext else 0)
        entry_idx = 0
        
        for f in files_to_show[:MAX_FILES_PER_DIR]:
            entry_idx += 1
            is_last_entry = entry_idx == total_entries
            file_connector = "└── " if is_last_entry else "├── "
            
            # Get file size
            try:
                size = os.path.getsize(os.path.join(path, f))
                size_str = f" ({format_size(size)})"
            except:
                size_str = ""
            
            lines.append(f"{new_prefix}{file_connector}{f}{size_str}")
        
        if len(files_to_show) > MAX_FILES_PER_DIR:
            entry_idx += 1
            is_last_entry = entry_idx == total_entries
            connector = "└── " if is_last_entry else "├── "
            lines.append(f"{new_prefix}{connector}... and {len(files_to_show) - MAX_FILES_PER_DIR} more files")
        
        # Show skipped files summary
        if skipped_by_ext:
            entry_idx += 1
            is_last_entry = entry_idx == total_entries
            connector = "└── " if is_last_entry else "├── "
            skip_summary = ', '.join([f"{count}{ext}" for ext, count in 
                                     sorted(skipped_by_ext.items(), key=lambda x: -x[1])[:5]])
            lines.append(f"{new_prefix}{connector}[skipped: {skip_summary}]")
        
        # Recurse into subdirectories
        for i, d in enumerate(dirs):
            _walk_dir(
                os.path.join(path, d),
                new_prefix,
                i == len(dirs) - 1 and entry_idx == total_entries
            )
            stats['total_dirs'] += 1
    
    _walk_dir(rootdir)
    return '\n'.join(lines), dict(stats)

# ============================================================================
# FILE CONTENT EXTRACTION
# ============================================================================

def extract_ipynb_code(filepath: str) -> str:
    """Extract code cells from Jupyter notebook."""
    content_parts = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
        
        cells = notebook.get('cells', [])
        code_cells = [c for c in cells if c.get('cell_type') == 'code']
        markdown_cells = [c for c in cells if c.get('cell_type') == 'markdown']
        
        content_parts.append(f"# Jupyter Notebook: {len(code_cells)} code cells, {len(markdown_cells)} markdown cells\n")
        
        for i, cell in enumerate(cells):
            cell_type = cell.get('cell_type', 'unknown')
            source = cell.get('source', [])
            
            if isinstance(source, list):
                source = ''.join(source)
            
            if cell_type == 'code':
                content_parts.append(f"\n# --- Cell {i+1} [Code] ---")
                content_parts.append(source)
            elif cell_type == 'markdown' and len(source) < 500:
                # Include short markdown cells as comments
                content_parts.append(f"\n# --- Cell {i+1} [Markdown] ---")
                for line in source.split('\n'):
                    content_parts.append(f"# {line}")
        
        return '\n'.join(content_parts)
        
    except Exception as e:
        return f"Error reading notebook: {e}"

def summarize_json_structure(data, max_depth: int = 3, current_depth: int = 0, 
                            max_items: int = 5, indent: str = "") -> str:
    """Create a summary of JSON structure."""
    if current_depth >= max_depth:
        if isinstance(data, dict):
            return f"{{...}} ({len(data)} keys)"
        elif isinstance(data, list):
            return f"[...] ({len(data)} items)"
        else:
            return repr(data)[:50]
    
    next_indent = indent + "  "
    
    if isinstance(data, dict):
        if not data:
            return "{}"
        lines = ["{"]
        items = list(data.items())[:max_items]
        for key, value in items:
            val_str = summarize_json_structure(value, max_depth, current_depth + 1, max_items, next_indent)
            lines.append(f'{next_indent}"{key}": {val_str},')
        if len(data) > max_items:
            lines.append(f'{next_indent}... +{len(data) - max_items} more keys')
        lines.append(f"{indent}}}")
        return '\n'.join(lines)
    
    elif isinstance(data, list):
        if not data:
            return "[]"
        if len(data) <= 3 and all(isinstance(x, (str, int, float, bool, type(None))) for x in data):
            return repr(data)
        
        lines = [f"[ // {len(data)} items"]
        for item in data[:max_items]:
            item_str = summarize_json_structure(item, max_depth, current_depth + 1, max_items, next_indent)
            lines.append(f'{next_indent}{item_str},')
        if len(data) > max_items:
            lines.append(f'{next_indent}... +{len(data) - max_items} more items')
        lines.append(f"{indent}]")
        return '\n'.join(lines)
    
    elif isinstance(data, str):
        if len(data) > 60:
            return f'"{data[:60]}..."'
        return repr(data)
    
    else:
        return repr(data)

def process_file_content(filepath: str, filename: str) -> Optional[str]:
    """Process a single file and return its content."""
    ext = os.path.splitext(filename)[1].lower()
    
    # Skip files that are too large
    try:
        file_size = os.path.getsize(filepath)
    except:
        return None
    
    if file_size > MAX_FILE_SIZE_PARTIAL:
        return f"[File too large: {format_size(file_size)} - skipped]"
    
    # Jupyter notebooks
    if filename.endswith('.ipynb'):
        return extract_ipynb_code(filepath)
    
    # JSON files
    if ext == '.json':
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                if file_size < 5000:
                    return f.read()
                
                data = json.load(f)
                summary = f"[JSON file: {format_size(file_size)}]\n\n"
                summary += summarize_json_structure(data, max_depth=4, max_items=5)
                
                if isinstance(data, list):
                    summary += f"\n\n# Total items: {len(data)}"
                elif isinstance(data, dict):
                    summary += f"\n\n# Top-level keys: {list(data.keys())}"
                
                return summary
        except json.JSONDecodeError as e:
            return f"[JSON parse error: {e}]"
        except Exception as e:
            return f"[Error reading file: {e}]"
    
    # JSONL files
    if ext == '.jsonl':
        try:
            lines = []
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= 5:
                        break
                    lines.append(line)
            
            if not lines:
                return "(Empty file)"
            
            result = f"[JSONL file: {format_size(file_size)}]\n"
            result += f"# First {len(lines)} lines:\n\n"
            result += ''.join(lines)
            result += "\n... (truncated)"
            return result
        except Exception as e:
            return f"[Error reading file: {e}]"
    
    # YAML/TOML config files (show full if small, truncate if large)
    if ext in {'.yaml', '.yml', '.toml'}:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            if len(content) > MAX_FILE_SIZE_FULL:
                lines = content.split('\n')[:MAX_LINES_PREVIEW]
                return '\n'.join(lines) + f"\n\n... [{len(content.split(chr(10))) - MAX_LINES_PREVIEW} more lines]"
            return content
        except Exception as e:
            return f"[Error reading file: {e}]"
    
    # Other text files
    if ext in TEXT_EXTENSIONS or filename in PRIORITY_FILES or ext == '':
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            if file_size > MAX_FILE_SIZE_FULL:
                lines = content.split('\n')[:MAX_LINES_PREVIEW]
                return '\n'.join(lines) + f"\n\n... [truncated - {format_size(file_size)} total]"
            
            return content
        except Exception as e:
            return f"[Error reading file: {e}]"
    
    return None

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def collect_files(rootdir: str, exclude_dirs: Set[str], 
                 summarize_dirs: Set[str], gitignore_patterns: Set[str]) -> List[Tuple[str, str, str]]:
    """Collect all files to process, sorted by priority."""
    files = []  # (priority, rel_path, full_path)
    
    for dirpath, dirnames, filenames in os.walk(rootdir):
        # Filter directories
        dirnames[:] = [d for d in dirnames 
                      if not should_exclude_dir(d, exclude_dirs) 
                      and d not in gitignore_patterns]
        
        # Skip summarized directories
        dirname = os.path.basename(dirpath)
        if dirname in summarize_dirs:
            dirnames.clear()
            continue
        
        for filename in filenames:
            if filename == OUTPUT_FILE or filename == os.path.basename(__file__):
                continue
            
            if filename in gitignore_patterns:
                continue
            
            ext = os.path.splitext(filename)[1].lower()
            if ext in EXTENSIONS_TO_SKIP:
                continue
            
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, rootdir)
            
            # Determine priority
            if filename in PRIORITY_FILES:
                priority = 0
            elif filename.lower().startswith('readme'):
                priority = 1
            elif ext in {'.py', '.js', '.ts', '.go', '.rs'}:
                priority = 2
            elif ext in {'.json', '.yaml', '.yml', '.toml'}:
                priority = 3
            else:
                priority = 4
            
            files.append((priority, rel_path, filepath))
    
    # Sort by priority, then by path
    files.sort(key=lambda x: (x[0], x[1]))
    return files

def process_files(files: List[Tuple[str, str, str]], output_handle) -> Dict:
    """Process all collected files and write to output."""
    stats = {'processed': 0, 'skipped': 0, 'errors': 0, 'total_chars': 0}
    
    for priority, rel_path, filepath in files:
        filename = os.path.basename(filepath)
        content = process_file_content(filepath, filename)
        
        if content is None:
            stats['skipped'] += 1
            continue
        
        if content.startswith('[Error'):
            stats['errors'] += 1
        
        output_handle.write(SEPARATOR)
        output_handle.write(f"FILE: {rel_path}\n")
        output_handle.write(SEPARATOR)
        output_handle.write(content + "\n")
        
        stats['processed'] += 1
        stats['total_chars'] += len(content)
    
    return stats

def main():
    parser = argparse.ArgumentParser(
        description='Generate project context for LLMs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_context.py
  python generate_context.py -o context.txt
  python generate_context.py --no-git --exclude tests docs
        """
    )
    parser.add_argument('-o', '--output', default=OUTPUT_FILE, 
                       help=f'Output file (default: {OUTPUT_FILE})')
    parser.add_argument('-d', '--directory', default=os.getcwd(),
                       help='Root directory to scan (default: current directory)')
    parser.add_argument('--no-git', action='store_true',
                       help='Skip git information')
    parser.add_argument('--no-gitignore', action='store_true',
                       help='Ignore .gitignore patterns')
    parser.add_argument('--exclude', nargs='*', default=[],
                       help='Additional directories to exclude')
    parser.add_argument('--summarize', nargs='*', default=[],
                       help='Additional directories to summarize')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress progress output')
    
    args = parser.parse_args()
    
    root_dir = os.path.abspath(args.directory)
    output_file = args.output
    
    if not args.quiet:
        print(f"📂 Scanning: {root_dir}")
    
    # Build exclusion sets
    exclude_dirs = DIRS_TO_EXCLUDE | set(args.exclude)
    summarize_dirs = DIRS_TO_SUMMARIZE | set(args.summarize)
    
    # Parse .gitignore
    gitignore_patterns = set() if args.no_gitignore else get_gitignore_patterns(root_dir)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("=" * 80 + "\n")
        f.write("PROJECT CONTEXT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Root: {root_dir}\n")
        f.write("=" * 80 + "\n\n")
        
        # Git information
        if not args.no_git:
            git_info = get_git_info(root_dir)
            if git_info:
                f.write("GIT INFORMATION:\n")
                f.write("-" * 40 + "\n")
                f.write(git_info + "\n\n")
        
        # Directory structure
        f.write("DIRECTORY STRUCTURE:\n")
        f.write("-" * 40 + "\n")
        tree, tree_stats = get_directory_structure(root_dir, exclude_dirs, 
                                                   summarize_dirs, gitignore_patterns)
        f.write(tree + "\n\n")
        
        # Collect and process files
        if not args.quiet:
            print("📄 Processing files...")
        
        files = collect_files(root_dir, exclude_dirs, summarize_dirs, gitignore_patterns)
        
        f.write("FILE CONTENTS:\n")
        file_stats = process_files(files, f)
        
        # Summary
        f.write("\n" + "=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Files processed: {file_stats['processed']}\n")
        f.write(f"Files skipped: {file_stats['skipped']}\n")
        f.write(f"Errors: {file_stats['errors']}\n")
        f.write(f"Estimated tokens: ~{estimate_tokens(str(file_stats['total_chars'])):,}\n")
    
    # Final output
    output_size = os.path.getsize(output_file)
    if not args.quiet:
        print(f"\n✅ Context generated: {output_file}")
        print(f"   Size: {format_size(output_size)}")
        print(f"   Files: {file_stats['processed']} processed, {file_stats['skipped']} skipped")
        print(f"   Estimated tokens: ~{estimate_tokens(output_size):,}")

if __name__ == "__main__":
    main()
