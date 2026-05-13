import os

MAGIC_SIGNATURES = [
    # Executables — highest priority
    (b'\x4D\x5A',             'Windows EXE/DLL',      True),
    (b'\x7F\x45\x4C\x46',    'Linux ELF Executable', True),
    (b'\xCA\xFE\xBA\xBE',    'Java Class/Mach-O',    True),
    (b'\xFE\xED\xFA\xCE',    'Mach-O 32-bit',        True),
    (b'\xFE\xED\xFA\xCF',    'Mach-O 64-bit',        True),
    (b'\xCE\xFA\xED\xFE',    'Mach-O Reverse',       True),

    # Documents
    (b'\x25\x50\x44\x46',    'PDF',                  False),  # %PDF
    (b'\x50\x4B\x03\x04',    'ZIP/DOCX/XLSX/PPTX',  False),  # PK
    (b'\xD0\xCF\x11\xE0',    'OLE/DOC/XLS',          False),  # Old Office

    # Images
    (b'\xFF\xD8\xFF',         'JPEG Image',           False),
    (b'\x89\x50\x4E\x47',    'PNG Image',             False),
    (b'\x47\x49\x46\x38',    'GIF Image',             False),
    (b'\x42\x4D',             'BMP Image',             False),

    # Archives
    (b'\x52\x61\x72\x21',    'RAR Archive',           False),
    (b'\x1F\x8B',             'GZIP Archive',          False),
    (b'\x37\x7A\xBC\xAF',    '7-Zip Archive',         False),
    (b'\x50\x4B\x05\x06',    'Empty ZIP',             False),
]

# Extensions that have no magic bytes (plain text) — no binary check expected
TEXT_EXTENSIONS = {'.txt', '.csv', '.json', '.xml', '.html', '.py',
                   '.js', '.md', '.log', '.bat', '.ps1', '.sh'}

# Extensions that MUST have a known binary signature
BINARY_EXTENSIONS = {
    '.pdf', '.docx', '.xlsx', '.pptx',
    '.xls', '.doc', '.jpg', '.jpeg',
    '.png', '.gif', '.bmp', '.zip',
    '.rar', '.7z',
}


def check_file_signature(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, 'rb') as f:
            magic = f.read(8)

        magic_hex = magic.hex().upper()

        real_type     = 'Unknown'
        is_executable = False

        for signature, type_label, executable in MAGIC_SIGNATURES:
            if magic.startswith(signature):
                real_type     = type_label
                is_executable = executable
                break

        expected_type = None
        is_spoofed    = False
        score         = 0
        risk          = 'SAFE'
        note          = ''

        # ── Case 1: Real type is a known executable ──
        if is_executable:
            is_spoofed = True
            score      = 85
            risk       = 'HIGH'
            note       = (f'Executable file ({real_type}) disguised as '
                          f'{ext.upper()} — extension spoofing detected')

        # ── Case 2: Binary extension but magic bytes are completely unknown ──
        # A real PDF/DOCX/PNG always has recognizable magic bytes.
        # If we see none, the file is either corrupted or deliberately obfuscated.
        elif ext in BINARY_EXTENSIONS and real_type == 'Unknown':
            is_spoofed = True
            score      = 60
            risk       = 'MEDIUM'
            note       = (f'File claims to be {ext.upper()} but has no '
                          f'recognizable file signature — possible obfuscation '
                          f'or corruption (magic bytes: {magic_hex})')

        # ── Case 3: Clean match ──
        else:
            note = f'File type verified: {real_type}'

        return {
            'real_type':     real_type,
            'expected_type': expected_type or ext,
            'is_executable': is_executable,
            'is_spoofed':    is_spoofed,
            'magic_bytes':   magic_hex,
            'risk':          risk,
            'score':         score,
            'note':          note,
        }

    except Exception as e:
        return {
            'real_type':     'ERROR',
            'expected_type': ext,
            'is_executable': False,
            'is_spoofed':    False,
            'magic_bytes':   '',
            'risk':          'ERROR',
            'score':         0,
            'note':          f'Could not read file: {e}',
        }