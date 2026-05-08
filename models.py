import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


MSG_TYPE_TEXT = 1
MSG_TYPE_IMAGE = 3
MSG_TYPE_VOICE = 34
MSG_TYPE_CARD = 42
MSG_TYPE_VIDEO = 43
MSG_TYPE_ANIMATION = 47
MSG_TYPE_LOCATION = 48
MSG_TYPE_SHARE = 49
MSG_TYPE_VOIP = 50
MSG_TYPE_SYSTEM = 10000

MSG_SUB_TYPE_LINK = 4
MSG_SUB_TYPE_LINK2 = 5
MSG_SUB_TYPE_FILE = 6
MSG_SUB_TYPE_GIF = 8
MSG_SUB_TYPE_MERGE_FORWARD = 19
MSG_SUB_TYPE_NOTE = 24
MSG_SUB_TYPE_MINI_PROGRAM = 33
MSG_SUB_TYPE_MINI_PROGRAM2 = 36
MSG_SUB_TYPE_CHANNEL = 51
MSG_SUB_TYPE_QUOTE = 57
MSG_SUB_TYPE_PAT = 62
MSG_SUB_TYPE_CHANNEL_LIVE = 63
MSG_SUB_TYPE_CHATROOM_NOTICE = 87
MSG_SUB_TYPE_MUSIC = 92
MSG_SUB_TYPE_PAY = 2000
MSG_SUB_TYPE_RED_ENVELOPE = 2001


@dataclass
class Message:
    seq: int = 0
    time: str = ""
    talker: str = ""
    talker_name: str = ""
    is_chatroom: bool = False
    sender: str = ""
    sender_name: str = ""
    is_self: bool = False
    type: int = 0
    sub_type: int = 0
    content: str = ""
    contents: Dict[str, Any] = field(default_factory=dict)

    def parse_media_info(self, raw_content: str):
        self.type, self.sub_type = _split_type(self.type)

        if self.type == MSG_TYPE_TEXT:
            self.content = raw_content
            return

        if self.type == MSG_TYPE_SYSTEM:
            self.sender = "system"
            self.sender_name = ""
            self.content = _parse_system_msg(raw_content)
            return

        if self.type == MSG_TYPE_IMAGE:
            md5 = _extract_xml_value(raw_content, "md5")
            if md5:
                self.contents["md5"] = md5
            self.content = "[image]"
            return

        if self.type == MSG_TYPE_VOICE:
            self.content = "[voice]"
            return

        if self.type == MSG_TYPE_VIDEO:
            md5 = _extract_xml_value(raw_content, "md5")
            rawmd5 = _extract_xml_value(raw_content, "rawmd5")
            if md5:
                self.contents["md5"] = md5
            if rawmd5:
                self.contents["rawmd5"] = rawmd5
            self.content = "[video]"
            return

        if self.type == MSG_TYPE_ANIMATION:
            cdnurl = _extract_xml_value(raw_content, "cdnurl")
            if cdnurl:
                self.contents["cdnurl"] = cdnurl
            self.content = "[animation]"
            return

        if self.type == MSG_TYPE_LOCATION:
            label = _extract_xml_value(raw_content, "label")
            poiname = _extract_xml_value(raw_content, "poiname")
            if label:
                self.contents["label"] = label
            if poiname:
                self.contents["poiname"] = poiname
            self.content = f"[location|{label or poiname or ''}]"
            return

        if self.type == MSG_TYPE_SHARE:
            app_type = _extract_xml_attr(raw_content, "appmsg", "type")
            if app_type:
                self.sub_type = int(app_type)
            title = _extract_xml_value(raw_content, "title")
            des = _extract_xml_value(raw_content, "des")
            url = _extract_xml_value(raw_content, "url")

            if self.sub_type in (MSG_SUB_TYPE_LINK, MSG_SUB_TYPE_LINK2):
                self.contents["title"] = title or ""
                self.contents["url"] = url or ""
                self.content = f"[link|{title or ''}]"
            elif self.sub_type == MSG_SUB_TYPE_FILE:
                md5 = _extract_xml_value(raw_content, "md5")
                self.contents["title"] = title or ""
                if md5:
                    self.contents["md5"] = md5
                self.content = f"[file|{title or ''}]"
            elif self.sub_type in (MSG_SUB_TYPE_MERGE_FORWARD, MSG_SUB_TYPE_NOTE, MSG_SUB_TYPE_CHATROOM_NOTICE):
                self.contents["title"] = title or ""
                self.contents["desc"] = des or ""
                label = "merge_forward" if self.sub_type == MSG_SUB_TYPE_MERGE_FORWARD else "note" if self.sub_type == MSG_SUB_TYPE_NOTE else "chatroom_notice"
                self.content = f"[{label}|{title or ''}]"
            elif self.sub_type in (MSG_SUB_TYPE_MINI_PROGRAM, MSG_SUB_TYPE_MINI_PROGRAM2):
                self.contents["title"] = title or ""
                self.contents["url"] = url or ""
                self.content = f"[mini_program|{title or ''}]"
            elif self.sub_type == MSG_SUB_TYPE_CHANNEL:
                self.contents["title"] = title or ""
                self.content = f"[channel|{title or ''}]"
            elif self.sub_type == MSG_SUB_TYPE_QUOTE:
                self.content = title or "[quote]"
                refer_content = _extract_xml_value(raw_content, "content", tag="refermsg")
                if refer_content:
                    self.contents["refer"] = refer_content
            elif self.sub_type == MSG_SUB_TYPE_MUSIC:
                self.contents["title"] = title or ""
                self.contents["url"] = url or ""
                self.content = f"[music|{title or ''}]"
            elif self.sub_type == MSG_SUB_TYPE_PAY:
                self.content = f"[transfer|{title or ''}]"
            elif self.sub_type == MSG_SUB_TYPE_RED_ENVELOPE:
                self.content = "[red_envelope]"
            else:
                self.content = f"[share|{title or ''}]"
            return

        if self.type == MSG_TYPE_VOIP:
            self.content = "[voip]"
            return

        if self.type == MSG_TYPE_CARD:
            self.content = "[card]"
            return

        self.content = raw_content[:200] if raw_content else f"[type_{self.type}]"

    def to_dict(self) -> dict:
        d = asdict(self)
        if not self.contents:
            del d["contents"]
        return d

    def to_plain_text(self, show_chatroom: bool = False, time_format: str = "%m-%d %H:%M:%S") -> str:
        sender = "me" if self.is_self else self.sender
        if self.sender_name:
            sender = f"{self.sender_name}({sender})"

        parts = [sender]
        if self.is_chatroom and show_chatroom:
            talker = f"{self.talker_name}({self.talker})" if self.talker_name else self.talker
            parts.append(f"[{talker}]")

        time_str = self.time
        if isinstance(self.time, str) and self.time:
            pass
        else:
            time_str = str(self.time)

        return f"{' '.join(parts)} {time_str}\n{self.content}\n"


@dataclass
class Contact:
    username: str = ""
    alias: str = ""
    remark: str = ""
    nick_name: str = ""
    is_friend: bool = True

    def display_name(self) -> str:
        return self.remark or self.nick_name or self.alias or self.username

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContactList:
    items: List[Contact] = field(default_factory=list)
    total: int = 0

    def to_dict(self) -> dict:
        return {"total": self.total, "items": [c.to_dict() for c in self.items]}


@dataclass
class ChatRoomUser:
    username: str = ""
    display_name: str = ""
    avatar: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChatRoom:
    name: str = ""
    owner: str = ""
    users: List[ChatRoomUser] = field(default_factory=list)
    user2display_name: Dict[str, str] = field(default_factory=dict)
    remark: str = ""
    nick_name: str = ""

    def display_name(self) -> str:
        return self.remark or self.nick_name or self.name

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "owner": self.owner,
            "remark": self.remark,
            "nick_name": self.nick_name,
            "user_count": len(self.users),
            "users": [u.to_dict() for u in self.users],
        }


@dataclass
class ChatRoomList:
    items: List[ChatRoom] = field(default_factory=list)
    total: int = 0

    def to_dict(self) -> dict:
        return {"total": self.total, "items": [c.to_dict() for c in self.items]}


@dataclass
class Session:
    username: str = ""
    nick_name: str = ""
    content: str = ""
    time: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionList:
    items: List[Session] = field(default_factory=list)
    total: int = 0

    def to_dict(self) -> dict:
        return {"total": self.total, "items": [s.to_dict() for s in self.items]}


def _split_type(t: int) -> tuple:
    if t > 0xFFFFFFFF:
        return t >> 32, t & 0xFFFFFFFF
    return t, 0


def _extract_xml_value(xml_str: str, key: str, tag: str = None) -> Optional[str]:
    if not xml_str or not isinstance(xml_str, str):
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        pattern = f'<{key}>(.*?)</{key}>'
        m = re.search(pattern, xml_str, re.DOTALL)
        return m.group(1).strip() if m else None

    if tag:
        parent = root.find(f'.//{tag}')
    else:
        parent = root

    if parent is None:
        return None

    el = parent.find(f'.//{key}')
    if el is not None and el.text:
        return el.text.strip()

    for el in root.iter(key):
        if el.text:
            return el.text.strip()
    return None


def _extract_xml_attr(xml_str: str, tag: str, attr: str) -> Optional[str]:
    if not xml_str or not isinstance(xml_str, str):
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        pattern = f'<{tag}[^>]*{attr}="([^"]*)"'
        m = re.search(pattern, xml_str)
        return m.group(1) if m else None

    el = root.find(f'.//{tag}')
    if el is not None:
        return el.get(attr)
    return None


def _parse_system_msg(xml_str: str) -> str:
    if not xml_str:
        return ""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return xml_str[:200]

    type_attr = root.get("type", "")
    for child in root:
        tag = child.tag.lower()
        if tag in ("revokemsg", "opmsg", "modmsg", "delmsg", "newmsg"):
            title = child.find("title")
            if title is not None and title.text:
                return title.text.strip()
            content = child.find("content")
            if content is not None and content.text:
                return content.text.strip()
        if tag == "pat":
            pat_title = child.find("title")
            if pat_title is not None and pat_title.text:
                return pat_title.text.strip()

    for child in root:
        if child.text and child.text.strip():
            return child.text.strip()[:200]

    return xml_str[:200]


def talker_to_table_name(talker: str) -> str:
    md5 = hashlib.md5(talker.encode()).hexdigest()
    return f"Msg_{md5}"
