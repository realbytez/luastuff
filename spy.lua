local ReGui = loadstring(game:HttpGet('https://raw.githubusercontent.com/depthso/Dear-ReGui/refs/heads/main/ReGui.lua'))()

local executor, version = identifyexecutor()
local functions = { request, http_request, (http and http.request) or nil }

local band
local bxor
local bnot
local lshift
local rshift1
local rshift
local random = {}

local sub = string.sub
local floor = math.floor

do -- https://gist.github.com/lukespragg/d3d939ec534db920eab8
    local MOD = 2 ^ 32
    local MODM = MOD - 1
    local function memoize(f)
        local mt = {}
        local t = setmetatable({}, mt)
        function mt:__index(k)
            local v = f(k)
            t[k] = v
            return v
        end

        return t
    end
    local function make_bitop_uncached(t, m)
        local function bitop(a, b)
            local res, p = 0, 1
            while a ~= 0 and b ~= 0 do
                local am, bm = a % m, b % m
                res = res + t[am][bm] * p
                a = (a - am) / m
                b = (b - bm) / m
                p = p * m
            end
            res = res + (a + b) * p
            return res
        end
        return bitop
    end
    local function make_bitop(t)
        local op1 = make_bitop_uncached(t, 2 ^ 1)
        local op2 =
            memoize(
                function(a)
                    return memoize(
                        function(b)
                            return op1(a, b)
                        end
                    )
                end
            )
        return make_bitop_uncached(op2, 2 ^ (t.n or 1))
    end

    local bxor1 = make_bitop({ [0] = { [0] = 0, [1] = 1 }, [1] = { [0] = 1, [1] = 0 }, n = 4 })
    bxor = function(a, b, c, ...)
        local z = nil
        if b then
            a = a % MOD
            b = b % MOD
            z = bxor1(a, b)
            if c then
                z = bxor(z, c, ...)
            end
            return z
        elseif a then
            return a % MOD
        else
            return 0
        end
    end

    band = function(a, b, c, ...)
        local z
        if b then
            a = a % MOD
            b = b % MOD
            z = ((a + b) - bxor1(a, b)) / 2
            return z
        elseif a then
            return a % MOD
        else
            return MODM
        end
    end

    bnot = function(x)
        return (-1 - x) % MOD
    end

    rshift1 = function(a, disp)
        if disp < 0 then
            return lshift(a, -disp)
        end
        return floor(a % 2 ^ 32 / 2 ^ disp)
    end

    rshift = function(x, disp)
        if disp > 31 or disp < -31 then
            return 0
        end
        return rshift1(x % MOD, disp)
    end

    lshift = function(a, disp)
        if disp < 0 then
            return rshift(a, -disp)
        end
        return (a * 2 ^ disp) % 2 ^ 32
    end

    local function seedgen()
        return os.clock() + tick() ^ 2
    end

    local original = seedgen

    local rng = function(seed)
        local a = 1103515245
        local c = 12345
        seed = (a * seed + c) % (2 ^ 31)
        local d = seed / (2 ^ 31)

        return function(min, max)
            min = min or 0
            max = max or 1
            if min > max then
                min, max = max, min
            end
            return d * (max - min) + min
        end
    end

    local calls = 0
    local gen = rng(seedgen())
    function random.int(min, max)
        gen = rng(seedgen())
        return floor(gen(min, max))
    end

    function random.string(len)
        local chars = "abcdefghijklmnopqrstuvxwyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        local r = ''
        for i = 1, len do
            local n = random.int(1, #chars)
            r = r .. sub(chars, n, n)
        end
        return r
    end

    function random.setseed(seed)
        if seed then
            seedgen = function() return seed end
        else
            seedgen = original
        end
    end
end

local function generatehwid()
    local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and random.int(0, 15) or random.int(8, 11)
        return string.format('%x', v)
    end):upper()
end

local function generateip() -- couldnt be bothered, thanks chatgpt
    local startipdec = 0
    local endipdec = 4294967295

    local randomipdec = random.int(startipdec, endipdec)

    local a = rshift(band(randomipdec, 0xFF000000), 24)
    local b = rshift(band(randomipdec, 0x00FF0000), 16)
    local c = rshift(band(randomipdec, 0x0000FF00), 8)
    local d = band(randomipdec, 0x000000FF)

    return string.format("%d.%d.%d.%d", a, b, c, d)
end

local fakehwid, fakeip = generatehwid(), generateip()
local actualhwid, actualip = game:GetService("RbxAnalyticsService"):GetClientId(), game:HttpGet("https://api.ipify.org/")

local function sanitize(s)
    s = s:gsub(actualhwid, fakehwid, 1000)
    s = s:gsub(actualip, fakeip, 1000)

    return s
end

local function search(s)
    local news = s
    local lowered = news:lower()
    local flagged = false
    if lowered:match(actualip) or lowered:match(fakeip) then -- ip info
        flagged = true
    end

    if lowered:match(actualhwid) or lowered:match(fakehwid) then -- hwid info
        flagged = true
    end

    if lowered:match("webhook") or lowered:match("ip") or lowered:match("httpbin") then -- logging / extra info
        flagged = true
    end

    return flagged
end

local serializer
do
    local sub = string.sub
    local find = string.find
    local format = string.format
    local gsub = string.gsub
    local dump = string.dump
    local byte = string.byte
    local rep = string.rep
    local concat = table.concat
    local insert = table.insert
    local type = type
    local tostring = tostring
    local pairs = pairs
    local huge = math.huge
    local nhuge = -huge
    
    local newline = '\n'
    local newline2 = '\\n'
    
    local tab = '\t'
    local tab2 = '\\t'
    
    local function mutate(str, q)
        local mutated = {}
        local length = #str
        local i = 0
        while i < length do
            i = i + 1
    
            local c = sub(str, i, i)
            if c == newline then
                c = newline2
            elseif c == tab then
                c = tab2
            else
                if (q == 1 or q == 3) and c == "'" then
                    c = "\\'"
                end
    
                if (q == 2 or q == 3) and c == '"' then
                    c = '\\"'
                end
            end
    
            insert(mutated, c)
        end
    
        return concat(mutated)
    end
    
    local function quotes(str)
        local dq = find(str, '"')
        local sq = find(str, "'")
    
        local c = 0
        if dq then c = c + 2 end
        if sq then c = c + 1 end
    
        return format('"%s"', mutate(str, c))
    end
    
    local function serializedata(data)
        if not data then
            return 'nil'
        end
    
        local typeof = type(data)
    
        if typeof == 'string' then
            return quotes(data)
        elseif typeof == 'boolean' then
            return (data and 'true' or 'false')
        end
    
        local ts = tostring(data)
    
        if typeof == 'number' then
            if data == huge then
                return 'math.huge'
            elseif data == nhuge then
                return '-math.huge'
            end
        elseif typeof == 'function' then
            return format("function(...) return loadstring(\"%s\")(...); end", gsub(dump(data), ".", function(k) return "\\" .. byte(k); end))
        elseif typeof == 'table' then
            return nil
        end
    
        return (ts)
    end
    
    serializer = function(tbl, level, checked)
        checked = checked or {}
        level = level or 1
    
        if checked[tbl] then
            return 'tbl'
        end
    
        checked[tbl] = true
    
        local result = { '{\n' }
        for i, v in pairs(tbl) do
            local sd = serializedata(v)
            if sd ~= nil then
                insert(result, format('%s[%s] = %s,\n', rep("\t", level), serializedata(i) or '', sd))
            else
                insert(result, format('%s[%s] = %s,\n', rep("\t", level), serializedata(i), serializer(v, level + 1, checked)))
            end
        end
    
        result = concat(result)
        result = format("%s\n%s}", sub(result, 0, #result - 2), rep('\t', level - 1))
        return result
    end
end

local LogEntries = {}
local DetailWindows = {}

local function copyToClipboard(text)
    if setclipboard then
        setclipboard(text)
    elseif toclipboard then
        toclipboard(text)
    else
        print("Clipboard not supported on this executor")
    end
end

local function createDetailWindow(entry)
    local detailWindow = ReGui:Window({
        Title = string.format("Request Details - %s %s", entry.method, entry.url),
        Size = UDim2.fromOffset(600, 500)
    })
    
    table.insert(DetailWindows, detailWindow)
    
    detailWindow:Separator({Text = "Request URL"})
    detailWindow:InputText({
        Value = entry.url,
        ReadOnly = true,
        Size = UDim2.new(1, -100, 0, 30)
    })
    
    local urlRow = detailWindow:Row()
    urlRow:Button({
        Text = "Copy URL",
        Callback = function()
            copyToClipboard(entry.url)
        end
    })
    
    -- Method and Status
    detailWindow:Separator({Text = "Request Info"})
    local infoRow = detailWindow:Row()
    infoRow:Label({Text = "Method: " .. entry.method})
    infoRow:Label({Text = "Status: " .. (entry.flagged and "FLAGGED" or "SAFE")})
    
    -- Request Data Section
    detailWindow:Separator({Text = "Request Data"})
    local requestEditor = detailWindow:CodeEditor({
        Text = entry.sent,
        ReadOnly = true,
        Size = UDim2.new(1, 0, 0, 150)
    })
    
    detailWindow:Button({
        Text = "Copy Request Data",
        Callback = function()
            copyToClipboard(entry.sent)
        end
    })
    
    -- Response Data Section
    detailWindow:Separator({Text = "Response Data"})
    local responseEditor = detailWindow:CodeEditor({
        Text = entry.received,
        ReadOnly = true,
        Size = UDim2.new(1, 0, 0, 150)
    })
    
    local responseRow = detailWindow:Row()
    responseRow:Button({
        Text = "Copy Response Data",
        Callback = function()
            copyToClipboard(entry.received)
        end
    })
    
    responseRow:Button({
        Text = "Copy All Data",
        Callback = function()
            local allData = string.format(
                "URL: %s\nMethod: %s\nStatus: %s\n\nRequest Data:\n%s\n\nResponse Data:\n%s",
                entry.url, entry.method, entry.flagged and "FLAGGED" or "SAFE", entry.sent, entry.received
            )
            copyToClipboard(allData)
        end
    })
    
    -- Close button
    detailWindow:Button({
        Text = "Close",
        Callback = function()
            detailWindow:Close()
        end
    })
end

local HTTPSpyWindow = ReGui:Window({
    Title = "HTTP Spy",
    Size = UDim2.fromOffset(900, 600)
})

local Stats = {
    TotalRequests = 0,
    FlaggedRequests = 0,
    UniqueHosts = {},
    Methods = {},
    StartTime = tick()
}

local Filters = {
    ShowFlagged = true,
    ShowSafe = true,
    SearchText = "",
    MethodFilter = "All",
    HostFilter = "All"
}

local Settings = {
    AutoSave = false,
    MaxLogs = 1000,
    Theme = "Dark",
    ShowTimestamp = true,
    ShowFullURL = false,
    AutoScroll = true
}



local function updateStats(entry)
    Stats.TotalRequests = Stats.TotalRequests + 1
    if entry.flagged then
        Stats.FlaggedRequests = Stats.FlaggedRequests + 1
    end
    
    local host = entry.url:match("https?://([^/]+)")
    if host then
        local found = false
        for _, existingHost in pairs(Stats.UniqueHosts) do
            if existingHost == host then
                found = true
                break
            end
        end
        if not found then
            table.insert(Stats.UniqueHosts, host)
        end
    end
    
    Stats.Methods[entry.method] = (Stats.Methods[entry.method] or 0) + 1
end

local LogTable = HTTPSpyWindow:Table({
    Border = true,
    RowBackground = true,
    MaxColumns = 5
})

local HeaderRow = LogTable:HeaderRow()
HeaderRow:Column():Label({Text = "Time"})
HeaderRow:Column():Label({Text = "Method"})
HeaderRow:Column():Label({Text = "Status"})
HeaderRow:Column():Label({Text = "URL"})
HeaderRow:Column():Label({Text = "Actions"})

local NotificationWindow = ReGui:Window({
    Title = "Notifications",
    Size = UDim2.fromOffset(300, 150),
    Visible = false
})

local function notif(title, message)
    NotificationWindow:SetVisible(true)
    NotificationWindow:Label({
        Text = string.format("[%s] %s", title, message),
        TextWrapped = true
    })
    
    spawn(function()
        wait(3)
        NotificationWindow:SetVisible(false)
    end)
end

local function createlog(url, method, flagged, received, sent)
    local timestamp = DateTime.now():FormatLocalTime("h:mm:ss A", "en-us")
    local isFlagged = flagged == "true"
    
    -- Store entry
    local entry = {
        id = #LogEntries + 1,
        timestamp = timestamp,
        url = url,
        method = method,
        flagged = isFlagged,
        sent = sent,
        received = received,
        size = #sent + #received
    }
    
    table.insert(LogEntries, entry)
    updateStats(entry)
    
    while #LogEntries > 1000 do
        table.remove(LogEntries, 1)
    end
    
    local tableRow = LogTable:Row()
    
    tableRow:Column():Label({
        Text = timestamp,
        TextColor3 = Color3.fromRGB(150, 150, 150)
    })
    
    -- Method column
    tableRow:Column():Label({
        Text = method,
        TextColor3 = Color3.fromRGB(100, 150, 255)
    })
    
    -- Status column
    tableRow:Column():Label({
        Text = isFlagged and "FLAGGED" or "SAFE",
        TextColor3 = isFlagged and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(100, 255, 100)
    })
    
    -- URL column
    local urlColumn = tableRow:Column()
    local displayUrl = string.len(url) > 60 and string.sub(url, 1, 57) .. "..." or url
    urlColumn:Label({
        Text = displayUrl,
        TextColor3 = isFlagged and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(100, 255, 100)
    })
    
    -- Actions column
    local actionsColumn = tableRow:Column()
    local actionsRow = actionsColumn:Row()
    
    actionsRow:SmallButton({
        Text = "Copy",
        Callback = function()
            copyToClipboard(url)
            print("Copied URL to clipboard")
        end
    })
    
    actionsRow:SmallButton({
        Text = "View",
        Callback = function()
            createDetailWindow(entry)
        end
    })
    
    actionsRow:SmallButton({
        Text = "Export",
        Callback = function()
            local allData = string.format(
                "URL: %s\nMethod: %s\nStatus: %s\nSize: %d bytes\n\nRequest Data:\n%s\n\nResponse Data:\n%s",
                url, method, isFlagged and "FLAGGED" or "SAFE", entry.size, sent, received
            )
            copyToClipboard(allData)
            print("Exported request data to clipboard")
        end
    })
    
    -- Debug print to console
    print(string.format("[HTTP Spy] %s %s %s - %s", 
        timestamp, method, url, isFlagged and "FLAGGED" or "SAFE"))
end

local hook = function(args, old)
    local newargs = args

    if getmetatable(newargs) then
        if not pcall(setmetatable(newargs, { __pairs = function(self) return next, self, nil end })) then
            notif("Error", "The anti HTTP spy used has anti-dump methods preventing secure logging from being possible.")
            return old(newargs)
        end
    end

    newargs.Method = newargs.Method or "GET"

    if newargs.Url then
        newargs.Url = sanitize(newargs.Url)
    end

    if newargs.Body then
        if type(newargs.Body) == 'string' then
            newargs.Body = sanitize(newargs.Body)
        end
    end

    local sent = serializer(newargs)
    local result = old(newargs)

    if result.Body then
        result.Body = sanitize(result.Body)
    end

    local flagged = search(newargs.Url or "") or search(newargs.Body or "") or search(result.Body or "")

    local received = {}
    local s, decoded = pcall(function() return game:GetService("HttpService"):JSONDecode(result.Body) end)

    if s and type(decoded) == 'table' then
        received = serializer({ Headers = result.Headers, Body = decoded })
    else
        received = serializer({ Headers = result.Headers, Body = result.Body })
    end

    createlog(newargs.Url, tostring(newargs.Method), tostring(flagged), received, sent)

    return result
end

for i, v in pairs(functions) do
    if v then
        local old = v
        old = hookfunction(v, newcclosure(function(args)
            return hook(args, old)
        end))

        if executor == 'Valyse' or executor == 'Electron' or executor == 'Krampus' then
            break
        end
    end
end



local function notif(title, message)
    NotificationWindow:SetVisible(true)
    NotificationWindow:Label({
        Text = string.format("[%s] %s", title, message),
        TextWrapped = true
    })
    
    spawn(function()
        wait(3)
        NotificationWindow:SetVisible(false)
    end)
end

local function createlog(url, method, flagged, received, sent)
    local timestamp = DateTime.now():FormatLocalTime("h:mm:ss A", "en-us")
    local isFlagged = flagged == "true"
    
    local entry = {
        id = #LogEntries + 1,
        timestamp = timestamp,
        url = url,
        method = method,
        flagged = isFlagged,
        sent = sent,
        received = received,
        size = #sent + #received
    }
    
    table.insert(LogEntries, entry)
    updateStats(entry)
    
    while #LogEntries > 1000 do
        table.remove(LogEntries, 1)
    end
    
    local tableRow = LogTable:Row()
    
    tableRow:Column():Label({
        Text = timestamp,
        TextColor3 = Color3.fromRGB(150, 150, 150)
    })
    
    tableRow:Column():Label({
        Text = method,
        TextColor3 = Color3.fromRGB(100, 150, 255)
    })
    
    tableRow:Column():Label({
        Text = isFlagged and "FLAGGED" or "SAFE",
        TextColor3 = isFlagged and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(100, 255, 100)
    })
    
    local urlColumn = tableRow:Column()
    local displayUrl = string.len(url) > 60 and string.sub(url, 1, 57) .. "..." or url
    urlColumn:Label({
        Text = displayUrl,
        TextColor3 = isFlagged and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(100, 255, 100)
    })
    
    local actionsColumn = tableRow:Column()
    local actionsRow = actionsColumn:Row()
    
    actionsRow:SmallButton({
        Text = "Copy",
        Callback = function()
            copyToClipboard(url)
            print("Copied URL to clipboard")
        end
    })
    
    actionsRow:SmallButton({
        Text = "View",
        Callback = function()
            createDetailWindow(entry)
        end
    })
    
    actionsRow:SmallButton({
        Text = "Export",
        Callback = function()
            local allData = string.format(
                "URL: %s\nMethod: %s\nStatus: %s\nSize: %d bytes\n\nRequest Data:\n%s\n\nResponse Data:\n%s",
                url, method, isFlagged and "FLAGGED" or "SAFE", entry.size, sent, received
            )
            copyToClipboard(allData)
            print("Exported request data to clipboard")
        end
    })
    
    print(string.format("[HTTP Spy] %s %s %s - %s", 
        timestamp, method, url, isFlagged and "FLAGGED" or "SAFE"))
end

local hook = function(args, old)
    local newargs = args

    if getmetatable(newargs) then
        if not pcall(setmetatable(newargs, { __pairs = function(self) return next, self, nil end })) then
            notif("Error", "The anti HTTP spy used has anti-dump methods preventing secure logging from being possible.")
            return old(newargs)
        end
    end

    newargs.Method = newargs.Method or "GET"

    if newargs.Url then
        newargs.Url = sanitize(newargs.Url)
    end

    if newargs.Body then
        if type(newargs.Body) == 'string' then
            newargs.Body = sanitize(newargs.Body)
        end
    end

    local sent = serializer(newargs)
    local result = old(newargs)

    if result.Body then
        result.Body = sanitize(result.Body)
    end

    local flagged = search(newargs.Url or "") or search(newargs.Body or "") or search(result.Body or "")

    local received = {}
    local s, decoded = pcall(function() return game:GetService("HttpService"):JSONDecode(result.Body) end)

    if s and type(decoded) == 'table' then
        received = serializer({ Headers = result.Headers, Body = decoded })
    else
        received = serializer({ Headers = result.Headers, Body = result.Body })
    end

    createlog(newargs.Url, tostring(newargs.Method), tostring(flagged), received, sent)

    return result
end

for i, v in pairs(functions) do
    if v then
        local old = v
        old = hookfunction(v, newcclosure(function(args)
            return hook(args, old)
        end))

        if executor == 'Valyse' or executor == 'Electron' or executor == 'Krampus' then
            break
        end
    end
end



local hook = function(args, old)
    local newargs = args

    if getmetatable(newargs) then
        if not pcall(setmetatable(newargs, { __pairs = function(self) return next, self, nil end })) then
            notif("Error", "The anti HTTP spy used has anti-dump methods preventing secure logging from being possible.")
            return old(newargs)
        end
    end

    newargs.Method = newargs.Method or "GET"

    if newargs.Url then
        newargs.Url = sanitize(newargs.Url)
    end

    if newargs.Body then
        if type(newargs.Body) == 'string' then
            newargs.Body = sanitize(newargs.Body)
        end
    end

    local sent = serializer(newargs)
    local result = old(newargs)

    if result.Body then
        result.Body = sanitize(result.Body)
    end

    local flagged = search(newargs.Url or "") or search(newargs.Body or "") or search(result.Body or "")

    local received = {}
    local s, decoded = pcall(function() return game:GetService("HttpService"):JSONDecode(result.Body) end)

    if s and type(decoded) == 'table' then
        received = serializer({ Headers = result.Headers, Body = decoded })
    else
        received = serializer({ Headers = result.Headers, Body = result.Body })
    end

    createlog(newargs.Url, tostring(newargs.Method), tostring(flagged), received, sent)

    return result
end

for i, v in pairs(functions) do
    if v then
        local old = v
        old = hookfunction(v, newcclosure(function(args)
            return hook(args, old)
        end))

        if executor == 'Valyse' or executor == 'Electron' or executor == 'Krampus' then
            break
        end
    end
end

