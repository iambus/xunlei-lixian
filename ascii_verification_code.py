# -*- coding: utf-8 -*-

from PIL import Image

__author__ = 'deadblue'

def convert_to_ascii(img_file):
    img = Image.open(img_file, 'r')
    img = img.convert('L')
    w,h = img.size
    # 生成矩阵
    martix = []
    for y in xrange(h / 2):
        row = []
        for x in xrange(w):
            p1 = img.getpixel((x, y * 2))
            p2 = img.getpixel((x, y * 2 + 1))
            if p1 > 192 and p2 > 192:
                row.append(0)
            elif p1 > 192:
                row.append(1)
            elif p2 > 192:
                row.append(2)
            else:
                row.append(3)
            #row.append(0 if p > 192 else 1)
        martix.append(row)
    return _martix_to_ascii(_crop_and_border(martix))

def _crop_and_border(martix):
    # 统计四周空白大小
    t,b,l,r = 0,0,0,0
    for y in xrange(len(martix)):
        if sum(martix[y]) == 0:
            t += 1
        else: break
    for y in xrange(len(martix)):
        if sum(martix[-1 - y]) == 0:
            b += 1
        else: break
    for x in xrange(len(martix[0])):
        if sum( map(lambda row:row[x], martix) ) == 0:
            l += 1
        else: break
    for x in xrange(len(martix[0])):
        if sum( map(lambda row:row[-1 - x], martix) ) == 0:
            r += 1
        else: break
    # 上下裁剪与补边
    w = len(martix[0])
    if t > 0:
        martix = martix[t-1:]
    else:
        martix.insert(0, [0] * w)
    if b > 1:
        martix = martix[:1-b]
    elif b == 0:
        martix.append([0] * w)
    # 左右裁剪与补边
    for ri in xrange(len(martix)):
        row = martix[ri]
        if l > 0:
            row = row[l-1:]
        else:
            row.insert(0, 0)
        if r > 1:
            row = row[:1-r]
        elif r == 0:
            row.append(0)
        martix[ri] = row
    return martix

def _martix_to_ascii(martix):
    buf = []
    for row in martix:
        rbuf = []
        for cell in row:
            if cell == 0:
                rbuf.append('#')
            elif cell == 1:
                rbuf.append('"')
            elif cell == 2:
                rbuf.append(',')
            elif cell == 3:
                rbuf.append(' ')
        buf.append(''.join(rbuf))
    return '\n'.join(buf)