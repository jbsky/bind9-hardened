#!/bin/sh
# Strip des bibliotheques partagees sans les reecrire en place.
#
# `strip` s'appuie sur libbfd, qui lie libz.so.1. Stripper une bibliotheque que
# strip a lui-meme mappee reecrit le fichier sous ses pieds : Segmentation
# fault, et un build qui echoue apres une installation reussie. Ecrire dans un
# fichier temporaire puis renommer contourne la classe entiere -- rename(2)
# laisse intact l'inode que les processus en cours ont deja ouvert.
set -eu
[ "$#" -gt 0 ] || { echo "strip_inplace: aucun fichier" >&2; exit 1; }
for f in "$@"; do
    [ -f "$f" ] || { echo "strip_inplace: $f introuvable" >&2; exit 1; }
    strip --strip-unneeded -o "$f.stripping" "$f"
    mv -f "$f.stripping" "$f"
done
