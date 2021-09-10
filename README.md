# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of Malpedia's automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2021-06-16

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2021-09-10
Samples (all):                              11170
Samples (detectable):                        4528
Families:                                    2154
-------------------------------------------------
Families covered by rules:                    995
Rules without FPs:                            986
Rules without FNs:                            919
'Clean' Rules:                                914
-------------------------------------------------
True Positives:                              4323
False Positives:                               20
True Negatives:                              5285
False Negatives:                              205
-------------------------------------------------
PPV / Precision:                            0.995
TPR / Recall:                               0.955
F1:                                         0.975
```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
