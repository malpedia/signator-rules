# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2024-11-11

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2024-11-11
Samples (all):                              14664
Samples (detectable):                        5928
Families:                                    3259
-------------------------------------------------
Families covered by rules:                   1468
Rules without FPs:                           1456
Rules without FNs:                           1386
'Clean' Rules:                               1378
-------------------------------------------------
True Positives:                              5714
False Positives:                               40
True Negatives:                              7240
False Negatives:                              214

-------------------------------------------------
PPV / Precision:                            0.993
TPR / Recall:                               0.964
F1:                                         0.978

```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
