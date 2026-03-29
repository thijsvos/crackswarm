# Credits and Attribution

## hashcat

**Author:** Jens "atom" Steube ([@hashcat](https://github.com/hashcat))
**License:** MIT
**Source:** https://github.com/hashcat/hashcat
**Website:** https://hashcat.net/hashcat/

This project orchestrates [hashcat](https://hashcat.net/hashcat/), the world's
fastest and most advanced password recovery tool. hashcat is developed and
maintained by Jens "atom" Steube and the hashcat team. All password cracking
is performed by hashcat -- this tool provides distributed coordination,
scheduling, and monitoring on top of it.

---

## Bundled Rules Files

### OneRuleToRuleThemStill.rule

**Author:** Will Hunt ([@stealthsploit](https://github.com/stealthsploit))
**Version:** 1.3
**Rules:** 48,439
**License:** MIT (custom rules); incorporated rules retain their original licenses
**Source:** https://github.com/stealthsploit/OneRuleToRuleThemStill
**Blog post:** https://in.security/2023/01/10/oneruletorulethemstill-new-and-improved/

OneRuleToRuleThemStill is an optimized hashcat rule set for password cracking,
refined by testing against real breach datasets to remove non-performing and
duplicate rules. It is the successor to OneRuleToRuleThemAll.

### Upstream Credits

The rule set incorporates rules from the following sources (as credited by the author):

- [hashcat](https://github.com/hashcat/hashcat) default rules (including `generated2` by [evilmog](https://github.com/evilmog))
- [Hob0Rules](https://github.com/praetorian-inc/Hob0Rules) by Praetorian
- [KoreLogic rules](http://contest-2010.korelogic.com/rules-hashcat.html)
- [NSA-RULES](https://github.com/NSAKEY/nsa-rules) (`NSAKEY.v2.dive.rule`)
- [duprule](https://github.com/mhasbini/duprule) (optimization tool)

### Usage

Upload the rules file to the coordinator, then reference it when creating
dictionary+rules tasks:

```bash
crackctl file upload rules/OneRuleToRuleThemStill.rule --type rules
crackctl task create --name "Dict+OTRTS" --hash-mode 1000 \
  --hash-file <hash-id> --wordlist <wordlist-id> --rules-file <rules-id>
```
