#!/usr/bin/env python
# -*- coding: utf-8 -*-

from website import init_create_app
app = init_create_app()

if __name__ == '__main__':
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5001
    )
