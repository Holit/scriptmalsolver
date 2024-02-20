from ....vm.forks.homestead.constants import HOMESTEAD_TX_GAS_SCHEDULE


#
# New gas costs for some opcodes
#

# EIP-1108:
GAS_ECADD = 150
GAS_ECMUL = 6000
GAS_ECPAIRING_BASE = 45_000
GAS_ECPAIRING_PER_POINT = 34_000

# EIP-1884:
GAS_SLOAD_EIP1884 = 800
GAS_BALANCE_EIP1884 = 700
GAS_EXTCODEHASH_EIP1884 = 700

# New gas cost for transaction data
# EIP-2028
GAS_TXDATANONZERO_EIP2028 = 16


ISTANBUL_TX_GAS_SCHEDULE = HOMESTEAD_TX_GAS_SCHEDULE._replace(
    gas_txdatanonzero=GAS_TXDATANONZERO_EIP2028,
)
