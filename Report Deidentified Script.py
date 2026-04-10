
# Medical Report Batch De-Identification Tool
# Input  : ZIP to class folders to PDF/image files
# Output : per-file _deidentified.pdf + _log.txt
# Console: only progress bar — no log spam



!pip install reportlab pdfplumber pillow tqdm --quiet
import os


os.system("apt-get install -y tesseract-ocr > /dev/null 2>&1")
!pip install pytesseract --quiet

import re
import zipfile
import shutil
import logging
from datetime import datetime
from pathlib import Path
from google.colab import files
from tqdm.notebook import tqdm

# Suppress console logging 
root_logger = logging.getLogger()
for h in root_logger.handlers[:]:
    root_logger.removeHandler(h); h.close()
root_logger.setLevel(logging.WARNING)

SUPPORTED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.bmp'}

PII_PATTERNS = [
    # ID number
    (r"(?i)(ID\.?\s*No\.?\s*[:\-]?\s*)[^\n]+",              r"\1[REDACTED]"),
    (r"(?i)(Patient'?s?\s*Name\s*[:\-]?\s*)[^\n]+",         r"\1[REDACTED]"),

    # Age
    (r"(?i)(Age\s*[:\-]?\s*)\d+\s*[YyMm]?(?:\s*\d+\s*[Mm])?\s*(?:\d+\s*[Dd])?", r"\1[REDACTED]"),

    # Sex
    (r"(?i)(Sex\s*[:\-]?\s*)[MFmf][a-z]*",                  r"\1[REDACTED]"),

    (r"(?i)Receive\s*[:\-]?\s*\d{1,2}/\d{1,2}/\d{4}",      "Receive: [DATE REDACTED]"),
    (r"(?i)Print\s*[:\-]?\s*\d{1,2}/\d{1,2}/\d{4}",        "Print: [DATE REDACTED]"),

    # Generic date formats
    (r"\b\d{2}/\d{2}/\d{4}\b",                              "[DATE REDACTED]"),
    (r"\b\d{4}-\d{2}-\d{2}\b",                              "[DATE REDACTED]"),
    (r"\b\d{1,2}-\d{1,2}-\d{4}\b",                          "[DATE REDACTED]"),

    # Referred by
    (r"(?i)(Refd\.?\s*by\s*[:\-]?\s*)[^\n]*",               r"\1[REDACTED]"),

    # BMDC reg
    (r"(?i)(BMDC\s*REG\s*NO\s*[:\-]?\s*)[^\n]+",            r"\1[REDACTED]"),

    (r"(?i)(DEPARTMENT\s+OF\s+RADIOLOGY\s*(?:&|AND)?\s*IMAGING[^\n]*)", r"[INSTITUTION REDACTED]"),
    (r"(?i)((?:General|Medical|City|Central|National|Combined|District)\s+(?:Hospital|Clinic|Health)[^\n]*)", r"[INSTITUTION REDACTED]"),
]

# INLINE PII PATTERNS — Pass 3 (body sweep)
INLINE_PII_PATTERNS = [
    # Repeated patient name line in body
    r"(?i)Patient'?s?\s*Name\s*[:\-]?\s*[^\n]+",

    # Inline age
    r"(?i)\bAge\s*[:\-]?\s*\d+\s*[YyMm]?\b",

    # Name with inline age format: "Sarkar-53Y" or "Sarkar 53Y"
    r"\b[A-Za-z][a-zA-Z]+(?:\s+[A-Za-z][a-zA-Z]+)*[\-\s]\d{2,3}[YyMm]\b",

    # Date in body
    r"\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b",

    # Phone numbers (BD format)
    r"(?:\+?880|0)1[3-9]\d{8}\b",

    # National ID / NID
    r"(?i)\bNID\s*[:\-]?\s*\d[\d\s\-]+\b",
]

# DOCTOR NAME PATTERNS — Pass 2
DOCTOR_NAME_PATTERNS = [
    r"\bDr\.?\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\b",
    r"\bProf\.?\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\b",
    r"(?i)(?:Consultant|Physician|Radiologist|Specialist)\s*[:\-]\s*[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3}",
    r"(?i)(?:Signed\s+by|Reported\s+by|Authorized\s+by)\s*[:\-]?\s*[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3}",
    r"[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3}(?=\s*\n\s*(?:MBBS|FCPS|MD|MS|MPhil|PhD))",
]

# REDACT TEXT  (3 passes)
def redact_text(text):
    """Returns (redacted_text, list_of_events)."""
    redacted = text
    events   = []

    # Pass 1: header PII 
    for pattern, replacement in PII_PATTERNS:
        # FIX 4: actual matched string capturing
        for m in re.finditer(pattern, redacted):
            matched_str = m.group(0).strip()
            # [REDACTED] if already then skip
            if "[REDACTED]" not in matched_str and "[DATE REDACTED]" not in matched_str:
                events.append({
                    "field":    pattern[:50],
                    "original": matched_str
                })
        redacted = re.sub(pattern, replacement, redacted)

    # Pass 2: doctor names 
    detected_names = set()
    for pattern in DOCTOR_NAME_PATTERNS:
        for m in re.findall(pattern, text):
            clean = re.sub(
                r"(?i)^(?:Dr\.?|Prof\.?|Consultant|Physician|Radiologist|"
                r"Specialist|Signed\s+by|Reported\s+by|Authorized\s+by)\s*[:\-]?\s*",
                "", m).strip()
            if clean:
                detected_names.add(clean)
        redacted = re.sub(pattern, "[PHYSICIAN NAME REDACTED]", redacted)
    for name in detected_names:
        events.append({"field": "PHYSICIAN NAME", "original": name})

    # Pass 3: inline PII sweep 
    for pattern in INLINE_PII_PATTERNS:
        for m in re.finditer(pattern, redacted):
            val = m.group(0).strip()
            if "[REDACTED]" not in val and "[DATE REDACTED]" not in val:
                events.append({"field": f"inline:{pattern[:40]}", "original": val})
        redacted = re.sub(pattern, "[REDACTED]", redacted)

    redacted = re.sub(r"Page\s+\[REDACTED\]\s+of\s+\d+", "Page 1 of 1", redacted)

    return redacted, events


# PARSE REDACTED TEXT → STRUCTURED FIELDS
def parse_report_fields(redacted_text):
    fields = {
        "exam_title":      "",
        "findings":        [],
        "comment":         "",
        "dd":              "",
        "advice":          "",
        "physician_creds": [],
        "raw_body":        "",
    }

    FINDING_LABELS = [
        "Trachea", "Diaphragm", "Heart", "Lung", "Lungs",
        "Bony thorax", "Bony Thorax", "Mediastinum", "Pleura",
        "Hilum", "Costophrenic", "Cardiothoracic", "C/T ratio",
        "Soft tissue", "Liver", "Spleen", "Kidney", "Kidneys",
        "Gall bladder", "Pancreas", "Aorta", "Bladder", "Uterus",
        "Bronchovascular", "Both CP", "Both dome", "Both domes",
        "Impression",
    ]

    CRED_KEYWORDS = [
        "MBBS", "FCPS", "MD", "MS", "MPhil", "PhD",
        "Specialist", "Professor", "Assistant", "Department",
        "CBMCHB", "X-ray", "USG", "CT scan", "MRI", "Imaging",
    ]

    SKIP_TAGS = [
        "[REDACTED]", "[DATE REDACTED]", "[PHYSICIAN",
        "BMDC REG NO", "[INSTITUTION REDACTED]",
        "[Signature", "Page 1 of",
    ]

    lines = [l.strip() for l in redacted_text.split('\n') if l.strip()]
    body_lines = []

    for line in lines:
        if any(tag in line for tag in SKIP_TAGS):
            continue

        if re.match(
            r"(?i)^(Chest|USG|X-?ray|CT|MRI|ECG|Echo|Abdomen|"
            r"Pelvis|KUB|Skull|Spine|X Ray|XRAY)", line
        ):
            fields["exam_title"] = line
            continue

        found = False
        for lbl in FINDING_LABELS:
            if re.match(rf"(?i)^{re.escape(lbl)}\s*[:\-]", line):
                value = re.split(r"[:\-]", line, maxsplit=1)[1].strip()
                fields["findings"].append((lbl, value))
                found = True
                break
            if re.match(rf"(?i)^{re.escape(lbl)}\s+(?:is|are|markings|fields|angles|domes|dome)\b", line):
                fields["findings"].append((lbl, line))
                found = True
                break
        if found:
            continue

        if re.match(r"(?i)^comment\s*[:\-]?", line):
            fields["comment"] = re.sub(r"(?i)^comment\s*[:\-]?\s*", "", line).strip()
            continue

        if re.match(r"(?i)^\(?D/?D\s*[:\-]?", line):
            fields["dd"] = line
            continue

        if re.match(r"(?i)^(Adv\.?|Advice\s*[:\-]?)", line):
            fields["advice"] = line
            continue

        if any(kw in line for kw in CRED_KEYWORDS):
            fields["physician_creds"].append(line)
            continue

        body_lines.append(line)

    if not fields["findings"]:
        fields["raw_body"] = "\n".join(body_lines)

    return fields


# BUILD PDF
def build_pdf(output_path, fields):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                    Paragraph, Spacer, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        topMargin=1.5*cm, bottomMargin=2*cm,
        leftMargin=2*cm, rightMargin=2*cm
    )
    styles  = getSampleStyleSheet()
    normal  = styles['Normal']
    small_s = ParagraphStyle('small_s', parent=normal, fontSize=8)
    story   = []

    # Header — institution name generic
    hdr = Table([['DEPARTMENT OF RADIOLOGY & IMAGING']], colWidths=[17*cm])
    hdr.setStyle(TableStyle([
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME',      (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 14),
        ('BOX',           (0,0), (-1,-1), 1.5, colors.black),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(hdr)
    story.append(Spacer(1, 0.3*cm))

    # Patient info
    info_data = [
        [Paragraph('<b>ID. No.</b>', normal),        ':',
         '[REDACTED]', 'Receive: [DATE REDACTED]', 'Print: [DATE REDACTED]'],
        [Paragraph("<b>Patient's Name</b>", normal), ':',
         '[REDACTED]', '', ''],
        [Paragraph('<b>Age</b>', normal),             ':',
         '[REDACTED]', Paragraph('<b>Sex</b>', normal), ': [REDACTED]'],
        [Paragraph('<b>Refd. by</b>', normal),        ':',
         '[REDACTED]', '', ''],
    ]
    info_tbl = Table(info_data, colWidths=[3.2*cm, 0.4*cm, 4.2*cm, 5*cm, 4.2*cm])
    info_tbl.setStyle(TableStyle([
        ('BOX',           (0,0), (-1,-1), 0.8, colors.black),
        ('INNERGRID',     (0,0), (-1,-1), 0.5, colors.black),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 0.8*cm))

    if fields.get("exam_title"):
        story.append(Paragraph(
            f'<u><b>{fields["exam_title"]}</b></u>', normal))
        story.append(Spacer(1, 0.5*cm))

    findings = fields.get("findings")
    if findings:
        for label, value in findings:
            row = Table(
                [[Paragraph(f'<b>{label}</b>', normal),
                  Paragraph(':', normal),
                  Paragraph(value, normal)]],
                colWidths=[3.8*cm, 0.5*cm, 12.7*cm]
            )
            row.setStyle(TableStyle([
                ('TOPPADDING',    (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(row)
    else:
        for line in fields.get("raw_body", "").split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), normal))
                story.append(Spacer(1, 0.1*cm))

    story.append(Spacer(1, 0.6*cm))

    if fields.get("comment"):
        story.append(Paragraph(f'<b>Comment: {fields["comment"]}</b>', normal))
    if fields.get("dd"):
        story.append(Paragraph(f'<b>{fields["dd"]}</b>', normal))
    if fields.get("advice"):
        story.append(Paragraph(f'<b>{fields["advice"]}</b>', normal))

    story.append(Spacer(1, 2*cm))

    story.append(Paragraph('[Signature REDACTED]', normal))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph('<b>[PHYSICIAN NAME REDACTED]</b>', normal))
    for cred in fields.get("physician_creds", []):
        story.append(Paragraph(cred, normal))
    story.append(Paragraph('BMDC REG NO: [REDACTED]', normal))
    story.append(Spacer(1, 1*cm))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.black))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        'This report has been electronically signed'
        + '&nbsp;' * 30 + 'Page 1 of 1',
        small_s
    ))
    doc.build(story)


# PER-FILE LOG
# FIX 4: Original value now actual text
def write_log(log_path, file_path, class_name,
              extracted_text, redacted_text, events, status, error_msg=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_pdf_name = log_path.stem.replace('_log', '_deidentified') + '.pdf'
    lines = [
        "=" * 60,
        "  DE-IDENTIFICATION LOG",
        "=" * 60,
        f"  Timestamp   : {ts}",
        f"  Class       : {class_name}",
        f"  Input file  : {file_path.name}",
        f"  Output PDF  : {out_pdf_name}",
        f"  Status      : {status}",
    ]
    if error_msg:
        lines.append(f"  Error       : {error_msg}")
    lines.append("")

    if events:
        lines.append(f"  PII redacted ({len(events)} instance(s)):")
        for ev in events:
            lines.append(f"    • Field    : {ev['field'][:55]}")
            lines.append(f"      Original : {repr(ev['original'])}")
    else:
        lines.append("  PII redacted : None detected")

    lines += [
        "",
        "  --- Extracted text (BEFORE) ---",
        *[f"  | {l}" for l in extracted_text.strip().split("\n")],
        "",
        "  --- Redacted text (AFTER) ---",
        *[f"  | {l}" for l in redacted_text.strip().split("\n")],
        "=" * 60,
    ]
    log_path.write_text("\n".join(lines), encoding="utf-8")


# PROCESS SINGLE FILE
def process_file(file_path, output_dir, class_name):
    import pdfplumber
    from PIL import Image
    import pytesseract

    suffix         = file_path.suffix.lower()
    extracted_text = ""
    out_pdf = output_dir / (file_path.stem + "_deidentified.pdf")
    out_log = output_dir / (file_path.stem + "_log.txt")

    try:
        if suffix == '.pdf':
            with pdfplumber.open(str(file_path)) as pdf:
                for page in pdf.pages:
                    extracted_text += (page.extract_text() or "") + "\n"
        elif suffix in {'.png', '.jpg', '.jpeg', '.tiff', '.bmp'}:
            img = Image.open(str(file_path))
            extracted_text = pytesseract.image_to_string(img)
        else:
            write_log(out_log, file_path, class_name, "", "", [],
                      "SKIPPED", "Unsupported file type")
            return False

        redacted_text, events = redact_text(extracted_text)
        fields = parse_report_fields(redacted_text)
        build_pdf(out_pdf, fields)
        write_log(out_log, file_path, class_name,
                  extracted_text, redacted_text, events, "SUCCESS")
        return True

    except Exception as e:
        write_log(out_log, file_path, class_name,
                  extracted_text, "", [], "FAILED", str(e))
        return False


# MAIN

print("Please upload your ZIP file...")
uploaded     = files.upload()
zip_filename = list(uploaded.keys())[0]
zip_size_mb  = os.path.getsize(zip_filename) / (1024 * 1024)
print(f" Uploaded: {zip_filename}  ({zip_size_mb:.1f} MB)")

extract_dir = Path("extracted_input")
output_dir  = Path("deidentified_output")
for d in [extract_dir, output_dir]:
    if d.exists(): shutil.rmtree(d)
    d.mkdir()

print(" Extracting ZIP...")
with zipfile.ZipFile(zip_filename, 'r') as z:
    z.extractall(extract_dir)

all_tasks = []
for class_folder in sorted(extract_dir.rglob("*")):
    if not class_folder.is_dir():
        continue
    class_name = class_folder.name
    class_out  = output_dir / class_name
    class_out.mkdir(parents=True, exist_ok=True)
    for f in sorted(class_folder.iterdir()):
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
            all_tasks.append((f, class_name, class_out))

total_files   = len(all_tasks)
total_classes = len({t[1] for t in all_tasks})
print(f"{total_classes} classes  |  {total_files} files")
print(f" Output per file: _deidentified.pdf + _log.txt\n")

success_count = 0
fail_count    = 0
class_summary = {}

with tqdm(total=total_files, desc="De-identifying", unit="file", ncols=80) as pbar:
    for file_path, class_name, class_out in all_tasks:
        if class_name not in class_summary:
            class_summary[class_name] = [0, 0]
        ok = process_file(file_path, class_out, class_name)
        if ok:
            success_count += 1
            class_summary[class_name][0] += 1
        else:
            fail_count += 1
            class_summary[class_name][1] += 1
        pbar.set_postfix({"ok": success_count, "fail": fail_count}, refresh=False)
        pbar.update(1)

print(f"\n{'='*50}")
print(f"  Success : {success_count}    Failed : {fail_count}")
print(f"  Classes : {total_classes}    Total  : {total_files}")
print(f"{'='*50}")
print("\nPer-class breakdown:")
for cls, (s, f) in class_summary.items():
    icon = "Done" if f == 0 else "Warning"
    print(f"  {icon}  {cls:35s}  {s:4d} ok   {f:3d} fail")

print("\n Zipping output folder...")
output_zip = f"deidentified_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
shutil.make_archive(output_zip.replace('.zip', ''), 'zip', output_dir)
zip_mb = Path(output_zip).stat().st_size / 1024 / 1024
print(f" Downloading ({zip_mb:.1f} MB)...")
files.download(output_zip)

print("\n Done!")
print(f"   Total: {success_count} PDF + {success_count} log = {success_count * 2} files")
