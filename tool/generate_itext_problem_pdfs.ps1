param(
  [string]$OutDir = "test\\assets\\pdfs"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $root
Set-Location $repoRoot

$jarPath = Join-Path $root "itext-2.1.3.jar"
$javaPath = Join-Path $root "ItextBadPdfGen.java"

if (-not (Test-Path $jarPath)) {
  $url = "https://repo1.maven.org/maven2/com/lowagie/itext/2.1.3/itext-2.1.3.jar"
  Write-Host "Baixando iText 2.1.3..."
  Invoke-WebRequest -Uri $url -OutFile $jarPath
}

$javaSource = @'
import java.io.*;
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;

public class ItextBadPdfGen {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Usage: ItextBadPdfGen <outDir>");
      System.exit(1);
    }
    File outDir = new File(args[0]);
    if (!outDir.exists()) outDir.mkdirs();

    makeSimplePdf(new File(outDir, "itext_base_simple.pdf"), "PDF simples", 1);
    makeSimplePdf(new File(outDir, "itext_base_multi.pdf"), "PDF multipaginas", 3);
    makeImagePdf(new File(outDir, "itext_base_image.pdf"), "PDF com imagem");
  }

  private static void makeSimplePdf(File file, String title, int pages) throws Exception {
    Document doc = new Document(PageSize.A4);
    PdfWriter.getInstance(doc, new FileOutputStream(file));
    doc.addTitle(title);
    doc.addAuthor("iText 2.1.3");
    doc.open();
    for (int i = 1; i <= pages; i++) {
      doc.add(new Paragraph("Pagina " + i));
      if (i < pages) doc.newPage();
    }
    doc.close();
  }

  private static void makeImagePdf(File file, String title) throws Exception {
    Document doc = new Document(PageSize.A4);
    PdfWriter writer = PdfWriter.getInstance(doc, new FileOutputStream(file));
    doc.addTitle(title);
    doc.open();
    PdfContentByte cb = writer.getDirectContent();
    cb.setRGBColorFill(30, 144, 255);
    cb.rectangle(100, 500, 200, 100);
    cb.fill();
    doc.add(new Paragraph("Retangulo desenhado"));
    doc.close();
  }
}
'@

Set-Content -Path $javaPath -Value $javaSource -Encoding ASCII

Write-Host "Compilando Java..."
& javac -cp $jarPath $javaPath

Write-Host "Gerando PDFs base..."
& java -cp "$root;$jarPath" ItextBadPdfGen (Join-Path $repoRoot $OutDir)

function Set-StartXrefToZero([byte[]]$bytes) {
  $token = [Text.Encoding]::ASCII.GetBytes("startxref")
  $pos = -1
  for ($i = $bytes.Length - $token.Length; $i -ge 0; $i--) {
    $ok = $true
    for ($j = 0; $j -lt $token.Length; $j++) {
      if ($bytes[$i + $j] -ne $token[$j]) { $ok = $false; break }
    }
    if ($ok) { $pos = $i; break }
  }
  if ($pos -lt 0) { return $bytes }
  $i = $pos + $token.Length
  while ($i -lt $bytes.Length -and ($bytes[$i] -eq 0x20 -or $bytes[$i] -eq 0x0D -or $bytes[$i] -eq 0x0A)) { $i++ }
  $start = $i
  while ($i -lt $bytes.Length -and $bytes[$i] -ge 0x30 -and $bytes[$i] -le 0x39) { $i++ }
  if ($i -le $start) { return $bytes }
  $len = $i - $start
  $zeros = ([string]::new('0', $len))
  $zeroBytes = [Text.Encoding]::ASCII.GetBytes($zeros)
  [Array]::Copy($zeroBytes, 0, $bytes, $start, $len)
  return $bytes
}

function RemoveEofMarker([byte[]]$bytes) {
  $marker = [Text.Encoding]::ASCII.GetBytes("%%EOF")
  for ($i = $bytes.Length - $marker.Length; $i -ge 0; $i--) {
    $ok = $true
    for ($j = 0; $j -lt $marker.Length; $j++) {
      if ($bytes[$i + $j] -ne $marker[$j]) { $ok = $false; break }
    }
    if ($ok) {
      $rep = [Text.Encoding]::ASCII.GetBytes("%%EO ")
      [Array]::Copy($rep, 0, $bytes, $i, $rep.Length)
      break
    }
  }
  return $bytes
}

function TruncateBytes([byte[]]$bytes, [int]$cut) {
  if ($bytes.Length -le $cut + 10) { return $bytes }
  $newLen = $bytes.Length - $cut
  $out = New-Object byte[] $newLen
  [Array]::Copy($bytes, 0, $out, 0, $newLen)
  return $out
}

$outDir = Join-Path $repoRoot $OutDir
$base1 = Join-Path $outDir "itext_base_simple.pdf"
$base2 = Join-Path $outDir "itext_base_multi.pdf"
$base3 = Join-Path $outDir "itext_base_image.pdf"

$bad1 = Join-Path $outDir "itext_2_1_3_bad_startxref.pdf"
$bad2 = Join-Path $outDir "itext_2_1_3_missing_eof.pdf"
$bad3 = Join-Path $outDir "itext_2_1_3_truncated.pdf"

Write-Host "Criando PDFs problemáticos..."

$bytes1 = [IO.File]::ReadAllBytes($base1)
$bytes1 = Set-StartXrefToZero $bytes1
[IO.File]::WriteAllBytes($bad1, $bytes1)

$bytes2 = [IO.File]::ReadAllBytes($base2)
$bytes2 = RemoveEofMarker $bytes2
[IO.File]::WriteAllBytes($bad2, $bytes2)

$bytes3 = [IO.File]::ReadAllBytes($base3)
$bytes3 = TruncateBytes $bytes3 512
[IO.File]::WriteAllBytes($bad3, $bytes3)

Write-Host "OK: $bad1"
Write-Host "OK: $bad2"
Write-Host "OK: $bad3"
