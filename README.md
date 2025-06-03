# P2P-Chat

## **1\. Allgemeiner Nachrichtenaufbau**

Byte 0    : Message ID (1 Byte)  
Byte 1-2  : Payload Length (2 Bytes, Big Endian)  
Byte 3-n  : Payload (je nach Typ)

## **2\. Message-IDs**

| ID (hex) | Typ | Zusätzliche Informationen |
| :---- | :---- | :---- |
| 0x01 | REGISTER |  |
| 0x11 | REGISTER\_RESPONSE |  |
| 0x02 | GET\_PEERS | Kein Payload benötigt |
| 0x12 | SEND\_PEERS |  |
| 0x03 | PEERS\_CHANGED |  |
| 0x04 | SEND_BOADCAST |  |
| 0x14 | MESSAGE_FROM_SERVER |  |
| 0xFF | ERROR\_MESSAGE |  Nicht genutzt |

## **3\. Datenobjekte**
### Peer
| Länge in Bytes | Beschreibung |
| :---- | :---- |
| 1 | Länge des Nicknames |
| n | UTF-8 kodierter Nickname |
| 4 | IP (z.B 192.168.1.1 \-\> C0 A8 01 01\) |
| 2 | UDP-Port, Big Endian |

## **4\. Weitere Informationen zu dem Payload spezifischer Befehlen**

### REGISTER: 
Der Payload des REGISTER-Befehls besteht aus genau einem [Peer-Eintrag](#peer).
<br />
Damit registriert sich der Client mit Nickname, IP-Adresse und UDP-Port beim Server.

### REGISTER\_RESPONSE:
Der Payload des REGISTER_RESPONSE-Befehls besteht aus einem Status-Code, der das Ergebnis der Registrierung angibt.
| Länge in Bytes | Beschreibung |
| :---- | :---- |
| 1 | Status Code |

 

| Status Codes: |  |
| :---- | :---- |
| 0x01 | Registrierung erfolgreich |
| 0x02 | Registrierung fehlgeschlagen |

### SEND\_PEERS:
Der Payload des SEND_PEERS-Befehls besteht aus meheren [Peer-Eintrag](#peer), außerdem wird die Anzahl der Peers mitgegeben.

| Länge in Bytes | Beschreibung |
| :---- | :---- |
| 1 | Anzahl der Einträge |
| variabel | Jeder Peer wird definiert. |
 
### PEERS\_CHANGED:

| Länge in Bytes | Beschreibung |
| :---- | :---- |
| variable | [Peer-Eintrag](#peer) |
| 1 | Status Code |

| Status Codes: |  |
| :---- | :---- |
| 0x01 | Peer wurde entfernt |
| 0x02 | Peer wurde registriert |

### SEND_BOADCAST:
Der Payload besteht ausschließlich aus einer UTF-8-kodierten Nachricht.
Die Länge der Nachricht ergibt sich aus dem allgemeinen Nachrichtenaufbau (siehe Abschnitt 1. Allgemeiner Nachrichtenaufbau) und muss dort im Feld Payload Length angegeben werden.
        Aufbau: Allgemeiner Nachrichtenaufbau

### MESSAGE_FROM_SERVER
Der Payload besteht ausschließlich aus einer UTF-8-kodierten Nachricht.
Die Länge der Nachricht ergibt sich aus dem allgemeinen Nachrichtenaufbau (siehe Abschnitt 1. Allgemeiner Nachrichtenaufbau) und muss dort im Feld Payload Length angegeben werden.
# Netzwerkprotokoll-Dokumentation

Dieses Dokument beschreibt den Aufbau der verschiedenen Nachrichtentypen innerhalb eines Peer-to-Peer-Kommunikationsprotokolls.

---

## 📡 `0x05` CONNECTION_REQUEST

**Typ:** UDP-Anfrage an einen anderen Client

### Aufbau:
| Feld             | Größe     | Beschreibung                |
|------------------|-----------|-----------------------------|
| ID               | 1 Byte    | Nachrichtentyp (0x05)       |
| Payloadlength    | 2 Byte    | Länge des Payloads          |

### Payload:
| Feld             | Größe     | Beschreibung                  |
|------------------|-----------|-------------------------------|
| Eigene IP-Adresse| 4 Byte    | IPv4-Adresse des Senders      |
| Eigener TCP-Port | 2 Byte    | TCP-Port des Senders          |

---

## 🔗 `0x15` PEER_CONNECTING

**Typ:** TCP-Antwort auf eine UDP-Anfrage

### Aufbau:
| Feld             | Größe     | Beschreibung                |
|------------------|-----------|-----------------------------|
| ID               | 1 Byte    | Nachrichtentyp (0x15)       |
| Payloadlength    | 2 Byte    | Länge des Payloads          |

### Payload:
| Feld              | Größe        | Beschreibung                          |
|-------------------|--------------|---------------------------------------|
| Nickname          | n Byte       | Anzeigename des Peers                 |
| Verifizierung     | 1 Byte       | Quersumme des Namens zur Prüfung      |

---

## 💬 `0x25` MESSAGE_TO_PEER

**Typ:** Allgemeiner Nachrichtenaufbau (z. B. Chatnachricht)

### Aufbau:
* Wird nach allgemeinem Nachrichtenformat strukturiert (Details nicht in diesem Dokument enthalten)

---

> ✏️ **Hinweis:** Alle Längenangaben beziehen sich auf die Byte-Größe der jeweiligen Felder.
