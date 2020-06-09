#!/usr/bin/env python
# -*- coding: utf-8 -*-

from markupsafe import Markup
from .lang.zh_cn import Lang


def build_toolbar(*args):
    btn = ['refresh', 'add', 'edit', 'del']
    btns = [x for x in args if x in btn]
    btnAttr = {
        'refresh': ['javascript:;', 'btn btn-primary btn-refresh', 'fa fa-refresh', '', Lang['refresh']],
        'add': ['javascript:;', 'btn btn-success btn-add', 'fa fa-plus', Lang['add'], Lang['add']],
        'edit': ['javascript:;', 'btn btn-success btn-edit btn-disabled disabled', 'fa fa-pencil', Lang['edit'], Lang['edit']],
        'del': ['javascript:;', 'btn btn-danger btn-del btn-disabled disabled', 'fa fa-trash', Lang['delete'], Lang['delete']],
    }

    html = []
    for k in btns:
        href, classs, icon, text, title = btnAttr[k]
        html.append('<a href="{0}" class="{1}" title="{2}"><i class="{3}"></i>{4}</a>'.format(
            href, classs, title, icon, text
        ))

    return Markup(' '.join(html))
