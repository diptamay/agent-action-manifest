#!/usr/bin/env python3
"""Render this repository's uncompressed draw.io diagrams to a vector PDF.

Supports the rectangles, text, explicit waypoints and anchored orthogonal arrows
used by this source. Rejects relative vertex geometry and overflowing text. Requires reportlab and
Arial TrueType fonts (--font-dir). This is a source-driven renderer, not draw.io.
"""
from pathlib import Path
from html import escape
import argparse, math, re, xml.etree.ElementTree as ET
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph


def style(value):
    return dict(piece.split('=', 1) for piece in value.split(';') if '=' in piece)


def geometry(cell):
    g = cell.find('mxGeometry')
    if g is None or g.get('relative') == '1':
        raise ValueError('Unsupported vertex geometry: '+cell.get('id', ''))
    return tuple(float(g.get(k, '0')) for k in ('x', 'y', 'width', 'height'))


def blocks(cell, s):
    value = cell.get('value', '')
    default_size = float(s.get('fontSize', 17))
    matches = re.findall(r'<div(?: style="([^"]*)")?>(.*?)</div>', value, re.S)
    if not matches:
        value = value if s.get('html') == '1' else escape(value)
        return [(value.replace('\n', '<br/>'), default_size, s.get('fontStyle') == '1', 0)]
    output = []
    for css, value in matches:
        size = re.search(r'font-size:([\d.]+)px', css)
        margin = re.search(r'margin-bottom:([\d.]+)px', css)
        output.append((value, float(size[1]) if size else default_size,
                       'font-weight:700' in css, float(margin[1]) if margin else 0))
    return output


def render(source, output, font_dir):
    for name, filename in [('Diagram', 'Arial.ttf'), ('Diagram-Bold', 'Arial Bold.ttf'),
                           ('Diagram-Italic', 'Arial Italic.ttf'), ('Diagram-BoldItalic', 'Arial Bold Italic.ttf')]:
        pdfmetrics.registerFont(TTFont(name, str(font_dir/filename)))
    pdfmetrics.registerFontFamily('Diagram', normal='Diagram', bold='Diagram-Bold',
                                  italic='Diagram-Italic', boldItalic='Diagram-BoldItalic')
    root = ET.parse(source).getroot()
    pdf = canvas.Canvas(str(output), invariant=1, pageCompression=1)
    pdf.setTitle('Agent Action Manifest workflow and governed feedback')
    pdf.setAuthor('Agent Action Manifest')
    for diagram in root.findall('diagram'):
        model = diagram.find('mxGraphModel')
        width, height = float(model.get('pageWidth')), float(model.get('pageHeight'))
        pdf.setPageSize((width*.72, height*.72))
        pdf.saveState(); pdf.scale(.72, .72)
        cells = {c.get('id'):c for c in model.findall('./root/mxCell')}
        def line(points, s):
            pdf.setStrokeColor(HexColor(s.get('strokeColor', '#486979')))
            pdf.setLineWidth(float(s.get('strokeWidth', 1.7)))
            pdf.setDash([float(n) for n in s.get('dashPattern', '6 4').split()] if s.get('dashed') == '1' else [])
            p = pdf.beginPath(); p.moveTo(points[0][0], height-points[0][1])
            for x,y in points[1:]:p.lineTo(x,height-y)
            pdf.drawPath(p)
            pdf.setDash([])
            def arrow(a,b):
                angle=math.atan2(b[1]-a[1],b[0]-a[0]); size=9
                p=pdf.beginPath();p.moveTo(b[0],height-b[1])
                for sign in (-1,1):
                    x=b[0]-size*math.cos(angle)+sign*size*.43*math.sin(angle)
                    y=b[1]-size*math.sin(angle)-sign*size*.43*math.cos(angle)
                    p.lineTo(x,height-y)
                p.close();pdf.setFillColor(HexColor(s.get('strokeColor','#486979')));pdf.drawPath(p,fill=1,stroke=0)
            if s.get('endArrow', 'block') != 'none':arrow(points[-2],points[-1])
            if s.get('startArrow', 'none') != 'none':arrow(points[1],points[0])
        for cell in cells.values():
            if cell.get('edge') != '1':continue
            s=style(cell.get('style',''));g=cell.find('mxGeometry')
            def anchor(key,xkey,ykey,pointname):
                if cell.get(key) in cells:
                    x,y,w,h=geometry(cells[cell.get(key)])
                    return (x+float(s.get(xkey,.5))*w,y+float(s.get(ykey,.5))*h)
                point=g.find(f"mxPoint[@as='{pointname}']")
                if point is None:raise ValueError('Missing edge anchor '+cell.get('id'))
                return float(point.get('x')),float(point.get('y'))
            first=anchor('source','exitX','exitY','sourcePoint');last=anchor('target','entryX','entryY','targetPoint')
            points=[(float(p.get('x')),float(p.get('y'))) for p in g.findall('Array/mxPoint')]
            if not points and first[0]!=last[0] and first[1]!=last[1]:
                mid=(first[0]+last[0])/2;points=[(mid,first[1]),(mid,last[1])]
            points=[first,*points,last]
            points=[p for i,p in enumerate(points) if i==0 or p!=points[i-1]]
            line(points,s)
        for cell in cells.values():
            if cell.get('vertex') != '1':continue
            x,y,w,h=geometry(cell);s=style(cell.get('style',''))
            fill=s.get('fillColor','none');stroke=s.get('strokeColor','none')
            if fill!='none':pdf.setFillColor(HexColor(fill))
            if stroke!='none':pdf.setStrokeColor(HexColor(stroke))
            pdf.setLineWidth(float(s.get('strokeWidth',1)))
            if fill!='none' or stroke!='none':
                if s.get('rounded')=='1':pdf.roundRect(x,height-y-h,w,h,8,fill=fill!='none',stroke=stroke!='none')
                else:pdf.rect(x,height-y-h,w,h,fill=fill!='none',stroke=stroke!='none')
            pad=float(s.get('spacing',0));available=w-2*pad
            paragraphs=[]
            for text,size,bold,margin in blocks(cell,s):
                text=re.sub(r'<br\s*/?>','<br/>',text)
                if not text:continue
                p=Paragraph(text,ParagraphStyle('cell',fontName='Diagram-Bold' if bold else 'Diagram',
                    fontSize=size,leading=size*1.22,textColor=HexColor(s.get('fontColor','#17384B')),
                    alignment={'left':0,'center':1,'right':2}.get(s.get('align'),0)))
                _,ph=p.wrap(available,10000);paragraphs.append((p,ph,margin))
            needed=sum(ph+margin for _,ph,margin in paragraphs)
            if needed>h-2*pad+.2:raise ValueError(f'Text overflow on {diagram.get("name")}/{cell.get("id")}: {needed:.1f} > {h-2*pad:.1f}')
            top=y+pad
            if s.get('verticalAlign')=='middle':top=y+(h-needed)/2
            for p,ph,margin in paragraphs:
                p.drawOn(pdf,x+pad,height-top-ph);top+=ph+margin
        pdf.restoreState();pdf.showPage()
    pdf.save()
    print(f'Rendered {len(root.findall("diagram"))} pages from {source.name}')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--font-dir',type=Path,default=Path('/System/Library/Fonts/Supplemental'))
    args=parser.parse_args()
    render(args.source,args.output or args.source.with_suffix(args.source.suffix+'.pdf'),args.font_dir)
