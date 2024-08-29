# Qradar_Investigations
This document contains Qradar queries for SOC investigation purposes. These prompts can be copied and pasted directly into Qradar, with "KeyArtifact" replaced by the appropriate search term relevant to your investigation.


## AQL Query for Failed Login Attempts by a Specific User.
This AQL query retrieves details about failed login attempts for a specific user over the past 24 hours. It filters events to show those where the eventName is 'Login Failed' and the username matches 'KeyArtifact'. The results include the source and destination IP addresses, the event name, event type, and the username involved. This query helps in identifying and analyzing failed login attempts for a given user within the last day.
```AQL
SELECT 
    sourceIP, 
    destinationIP, 
    eventName, 
    eventType, 
    username 
FROM events 
WHERE eventName = 'Login Failed'
AND username = 'KeyArtifact'
AND time >= NOW() - 24h
```

## AQL Query for Threat IP Prevalence (Last 7 Days):
This query will provide you with a detailed overview of how often the threat IP has appeared in the last week, including counts and unique IP details. Adjust the threat IP as needed for your specific investigation.

```AQL
SELECT 
    sourceIP, 
    destinationIP, 
    COUNT(*) AS Occurrences, 
    DC(sourceIP) AS UniqueSourceIPs, 
    DC(destinationIP) AS UniqueDestinationIPs, 
    earliest(time) AS FirstSeen, 
    latest(time) AS LastSeen 
FROM events 
WHERE (sourceIP = 'KeyArtifact' OR destinationIP = 'KeyArtifact')
AND time >= NOW() - 7d
GROUP BY sourceIP, destinationIP
ORDER BY Occurrences DESC
```

## AQL Query for User Activity (Last 24 Hours):
This query will provide detailed information on the specified user's activity over the past 24 hours, including event counts and timestamps.

```AQL
SELECT 
    username, 
    sourceIP, 
    destinationIP, 
    eventName, 
    eventType, 
    COUNT(*) AS Occurrences, 
    earliest(time) AS FirstSeen, 
    latest(time) AS LastSeen 
FROM events 
WHERE username = 'KeyArtifact'
AND time >= NOW() - 1d
GROUP BY username, sourceIP, destinationIP, eventName, eventType
ORDER BY FirstSeen DESC
```
