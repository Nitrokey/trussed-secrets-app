# Design

The following design choices have been implemented to strike a balance between the secure utilization and
user-friendliness of the Secrets App project. These decisions originated from the [YKOATH] protocol and were compared with
alternative offline solutions. Throughout this process, the aim was to ensure a basic level of safeguarding against
malware threats by incorporating physical user presence confirmation for critical operations.

[YKOATH]: https://developers.yubico.com/OATH/YKOATH_Protocol.html

|                        | 1\. Daily use                                               | 2\. Registration / modification                                                 | 3\. Factory Reset confirmation                                                                                           | 4\. PINs / passphrases | 5\. PIN change guard         | 6\. Attack vector protection | 7\. Token validation period                     |
|------------------------|-------------------------------------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|------------------------|------------------------------|------------------------------|-------------------------------------------------|
| Secrets App v0.10+     | Touch button if set, and/or<br>PIN if set on the Credential | Touch button always, before processing (to prevent PIN attempt counter use up). | Touch button                                                                                                             | Single PIN only        | Current PIN and Touch button | Local / Malware              | Each request, where PIN is needed (per request) |
| Secrets App Next (TBD) | (no changes)                                                | (no changes)                                                                    | \- Touch button<br>\- Within 10 seconds of power cycle only<br>\- Significant UX event – LED animation red/blue blinking | (no changes)           | (no changes)                 | (no changes)                 | (no changes)                                    |



|                        | Comments                                                                                                                                                                                                                          |
|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Secrets App v0.10+     | Do not require PIN for user data, but offer such possibility. Keep all encrypted. PIN-encrypted Credentials are not listed until PIN is provided. Touch button should always protect PIN use to prevent local malware DOS attack. |
| Secrets App Next (TBD) | (no changes)                                                                                                                                                                                                                      |


Other:
- do not allow to overwrite credentials - always require explicit deletion of the credential with the same name
- remove YKOATH protocol compatibility, specifically authentication through challenge-response

Privacy concerns:
- the credential overwrite protection (for the Update and Register commands) can leak information about the presence of a PIN-encrypted credential with the same name. See below ticket for details:
  - https://github.com/Nitrokey/trussed-secrets-app/issues/101