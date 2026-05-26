#!/bin/bash
echo "===================="
echo "Estado del firewall IA"
echo "===================="
echo ""
echo "--- IPS bloqueadas por IA ---"
sudo nft list set inet filter ia_blocklist 2>/dev/null || echo "(set vacio)"
echo ""
echo "--- Whitelist ---"
sudo nft list set inet fliter whitelist
echo ""
echo "--- Contadores de reglas ---"
sudo nft list chain inet filter input | grep counter
echo ""
echo "--- Ultimas 10 lineas del log ---"
sudo journalctl -k --no-pager | grep "NFT-DROP" | tail -10
