#!/bin/bash
# scripts/fix_all_services.sh

echo "🛠️ PUCP Orchestrator - Reparación Completa de Servicios"
echo "======================================================="

# Hacer scripts ejecutables
chmod +x fix_slice_service.sh
chmod +x fix_image_service.sh  
chmod +x fix_network_database.sh
chmod +x check_all_services_fixed.sh

# Ejecutar reparaciones
echo "1. Reparando Network Database..."
./fix_network_database.sh

echo ""
echo "2. Reparando Slice Service..."
./fix_slice_service.sh

echo ""
echo "3. Reparando Image Service..."
./fix_image_service.sh

echo ""
echo "4. Verificación final..."
sleep 5
./check_all_services_fixed.sh

echo ""
echo "🏁 Reparación completada!"
echo ""
echo "Si aún hay problemas:"
echo "  - Revisar: sudo journalctl -u pucp-* --since '5 minutes ago'"
echo "  - Reiniciar todo: sudo systemctl restart pucp-*"
echo "  - Test manual: curl http://localhost/health"
