local Verifier = {}
local settings = {
    hwidenabled = false,
    hwidlink = "",
    mapping = {}
}
local cachedHwids = {}


-- Download HWID list from URL
local function fetchHwidList(url)
    if cachedHwids[url] then
        return cachedHwids[url]
    end
    
    local success, result = pcall(function()
        return game:HttpGet(url, true)
    end)
    
    if not success then
        warn("Failed to fetch HWID list: " .. result)
        return {}
    end
    
    local hwids = {}
    for line in result:gmatch("[^\r\n]+") do
        if line:match("%S") then -- non-empty line
            table.insert(hwids, line)
        end
    end
    
    cachedHwids[url] = hwids
    return hwids
end

-- Decrypt HWID using mapping
local function decryptHwid(encryptedHwid, mapping)
    local decrypted = ""
    for emoji in encryptedHwid:gmatch("([%z\1-\127\194-\244][\128-\191]*)") do
        if mapping[emoji] then
            decrypted = decrypted .. mapping[emoji]
        else
            warn("Unknown emoji in encrypted HWID: " .. emoji)
            return nil
        end
    end
    return decrypted
end

-- Configure verifier settings
function Verifier.Settings(options)
    settings.hwidenabled = options.hwidenabled or false
    settings.hwidlink = options.hwidlink or ""
end

-- Set the decryption mapping
function Verifier.Mapping(mappingTable)
    settings.mapping = mappingTable or {}
end

-- Verify a player
function Verifier.Verify(player)
    if not settings.hwidenabled then
        return true -- HWID check disabled
    end
    
    if settings.hwidlink == "" then
        warn("HWID verification enabled but no HWID link provided")
        return false
    end
    
    local playerHwid = gethwid()
    local encryptedHwids = fetchHwidList(settings.hwidlink)
    
    -- Decrypt each HWID in the list and check for a match
    for _, encryptedHwid in ipairs(encryptedHwids) do
        local decryptedHwid = decryptHwid(encryptedHwid, settings.mapping)
        if decryptedHwid and decryptedHwid == playerHwid then
            return true -- HWID found in list
        end
    end
    
    return false -- HWID not found
end

return Verifier
