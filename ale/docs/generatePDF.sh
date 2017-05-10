#!/bin/bash
pandoc \
--from=markdown_mmd+fenced_code_blocks+backtick_code_blocks+fenced_code_attributes+tex_math_dollars+fancy_lists \
-S \
--smart \
--template ./template/UBAtemplate-2Columns.tex \
--listings  \
--latex-engine=pdflatex \
-o TP1.pdf \
TP1.md
