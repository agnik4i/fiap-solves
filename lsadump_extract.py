from volatility3.plugins.windows import hashdump
from volatility3.plugins.windows.registry import hivelist
from volatility3.framework.layers.registry import RegistryHive
from volatility3.plugins.windows.lsadump import Lsadump
from volatility3.framework.symbols.windows import versions

kernel = self.context.modules[self.config['kernel']]

syshive = sechive = None

for hive in hivelist.HiveList.list_hives(self.context, self.config_path, kernel.layer_name, kernel.symbol_table_name):
    name = hive.get_name().split("\\")[-1].upper()
    if name == "SYSTEM":
        syshive = hive
    if name == "SECURITY":
        sechive = hive

bootkey = hashdump.Hashdump.get_bootkey(syshive)
vista_or_later = versions.is_vista_or_later(context=self.context, symbol_table=kernel.symbol_table_name)
lsakey = Lsadump.get_lsa_key(sechive, bootkey, vista_or_later)

secret = Lsadump.get_secret_by_name(sechive, "DefaultPassword", lsakey, vista_or_later)

if secret:
    print("[+] DefaultPassword:")
    print(secret.decode(errors="ignore"))
else:
    print("[-] Fudeu.")

