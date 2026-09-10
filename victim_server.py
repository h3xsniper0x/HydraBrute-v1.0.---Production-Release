#!/usr/bin/env python3
"""
HydraBrute v2.1 - High-Throughput Asynchronous Network Authentication Testing Engine
Pure Python Implementation (Standard Library Only - Zero 3rd-Party Dependencies)

Features:
- Full Asyncio Non-Blocking Engine (High Concurrency & Low Resource Usage)
- Cross-Platform (Native Linux & Windows 10/11 Terminal Support)
- Dynamic In-Memory Rule Mutation (Leet, Suffixes, Casing)
- State Checkpointing & Interruption Resumption (.hbstate)
- Zero Unhandled Tracebacks with Layered Standard Logging
- HTTP-Basic over raw sockets (401 differential)
- HTTP-POST web form logins: form-urlencoded bodies, per-attempt CSRF token
  harvesting (html.parser), session cookie reuse (Set-Cookie parsing),
  redirect/fail-string differential analysis, automatic SSL/TLS wrapping
"""

import sys
import os
import re
import ssl
import time
import json
import base64
import socket
import asyncio
import logging
import argparse
import urllib.parse
from html.parser import HTMLParser
from typing import List, Tuple, Optional, Dict, Any, Generator, Set

__version__ = "2.1.0"
__tool_name__ = "HydraBrute"
__author__ = "Security Engineering Student"


# ==============================================================================
# 1. واجهة العرض والسجلات وإدارة الألوان (Terminal UI & Logging)
# ==============================================================================

class UI:
    """إدارة الألوان والتنسيق عبر الأنظمة المختلفة"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def setup(cls):
        if sys.platform == "win32":
            # تمكين معالجة ANSI Escape Sequences في ويندوز
            os.system('')

    @classmethod
    def color(cls, text: str, color_code: str) -> str:
        return f"{color_code}{text}{cls.RESET}"


def setup_logger(log_level: str = "INFO") -> logging.Logger:
    """تهيئة نظام السجلات وفق المعايير لمنع ظهور الـ Traceback للمستخدم"""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger(__tool_name__)
    logger.setLevel(numeric_level)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)
    return logger


# ==============================================================================
# 2. محرك تحوير وتوليد القواعد اللحظي (In-Memory Rule Mutation Engine)
# ==============================================================================

class RuleMutator:
    """توليد كلمات مرور ديناميكياً في الذاكرة لتفادي استهلاك أقراص التخزين"""

    LEET_MAP = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    COMMON_SUFFIXES = ['123', '2024', '2025', '2026', '!', '#', 'admin']

    @classmethod
    def mutate(cls, base_password: str) -> Set[str]:
        results = {base_password}

        # 1. Capitalization & Lowercase
        results.add(base_password.capitalize())
        results.add(base_password.upper())
        results.add(base_password.lower())

        # 2. Suffix Appending
        for suffix in cls.COMMON_SUFFIXES:
            results.add(f"{base_password}{suffix}")
            results.add(f"{base_password.capitalize()}{suffix}")

        # 3. Leet Speak Transformation
        leet_ver = "".join(cls.LEET_MAP.get(c.lower(), c) for c in base_password)
        results.add(leet_ver)
        results.add(f"{leet_ver}123")

        return results


# ==============================================================================
# 3. نظام استئناف الجلسات وإدارة نقاط التوقف (Session State Manager)
# ==============================================================================

class CheckpointManager:
    """حفظ واسترجاع حالة الفحص عند المقاطعة (Graceful Resumption)"""

    @staticmethod
    def get_state_filename(target: str, protocol: str) -> str:
        clean_target = target.replace(":", "_").replace("/", "_")
        return f".{clean_target}_{protocol}.hbstate"

    @classmethod
    def save_checkpoint(cls, target: str, protocol: str, completed_index: int, found_creds: List[Tuple[str, str]]):
        """عملية حفظ متزامنة (خارج حلقة الأحداث) لضمان الكتابة قبل إغلاق الـ Loop"""
        state_file = cls.get_state_filename(target, protocol)
        data = {
            "target": target,
            "protocol": protocol,
            "completed_index": completed_index,
            "found_credentials": found_creds,
            "timestamp": time.time()
        }
        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except OSError:
            pass

    @classmethod
    def load_checkpoint(cls, target: str, protocol: str) -> Optional[Dict[str, Any]]:
        state_file = cls.get_state_filename(target, protocol)
        if os.path.exists(state_file):
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return None
        return None

    @classmethod
    def clear_checkpoint(cls, target: str, protocol: str):
        state_file = cls.get_state_filename(target, protocol)
        if os.path.exists(state_file):
            try:
                os.remove(state_file)
            except OSError:
                pass


# ==============================================================================
# 4. أدوات مساعدة للبروتوكول (HTTP Response / Target Sanitization Helpers)
# ==============================================================================

def sanitize_target(target: str) -> Tuple[str, Optional[int], bool]:
    """تعقيم الهدف: إزالة http(s):// والشرطات المائلة، واستخراج المنفذ والمخطط"""
    t = (target or "").strip()
    was_https = False
    m = re.match(r"(?i)^(https?)://", t)
    if m:
        was_https = (m.group(1).lower() == "https")
        t = t[m.end():]
    t = t.split("/")[0].rstrip(".")
    host, port = t, None
    if t.count(":") == 1:
        h, p = t.rsplit(":", 1)
        if p.isdigit():
            host, port = h.strip(), int(p)
    return host, port, was_https


async def _read_http_response(reader: asyncio.StreamReader, timeout: float) -> Tuple[int, Dict[str, str], List[str], bytes]:
    """قراءة استجابة HTTP/1.1 كاملة (سطر الحالة + الرؤوس + الجسم) بدون مكتبات خارجية"""
    status_raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", status_raw)
    status_code = int(m.group(1)) if m else 0

    headers: Dict[str, str] = {}
    set_cookies: List[str] = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if line in (b"\r\n", b"\n", b""):
            break
        key_b, _, val_b = line.partition(b":")
        key = key_b.decode("latin-1").strip().lower()
        val = val_b.decode("latin-1").strip()
        if key == "set-cookie":
            set_cookies.append(val)
        elif key and key not in headers:
            headers[key] = val

    body = b""
    try:
        if "content-length" in headers:
            remaining = int(headers["content-length"])
            while remaining > 0:
                chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=timeout)
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
        else:
            # قراءة حتى إغلاق الاتصال (نظراً لطلب Connection: close)
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                body += chunk
    except asyncio.TimeoutError:
        pass  # الجزء المقروء من الجسم يكفي لتحليل الفشل/النجاح
    return status_code, headers, set_cookies, body


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """إغلاق آمن للمقبس لا يرفع استثناءات أبداً"""
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass


class _LoginFormParser(HTMLParser):
    """مستخرج الحقول المخفية من نماذج HTML باستخدام مكتبة html.parser القياسية"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_fields: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "input":
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if attr_map.get("type", "").lower() == "hidden" and attr_map.get("name"):
            self.hidden_fields[attr_map["name"]] = attr_map.get("value", "")


def _extract_hidden_fields(html_text: str, wanted_field: Optional[str] = None) -> Dict[str, str]:
    parser = _LoginFormParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass
    if wanted_field:
        wanted = wanted_field.lower()
        return {k: v for k, v in parser.hidden_fields.items() if k.lower() == wanted}
    return parser.hidden_fields


def _build_cookie_header(set_cookies: List[str]) -> str:
    """أخذ أول زوج name=value من كل Set-Cookie (دون خصائص المسار/الانتهاء)"""
    pairs = []
    for c in set_cookies:
        first = c.split(";", 1)[0].strip()
        if "=" in first:
            pairs.append(first)
    return "; ".join(pairs)


# ==============================================================================
# 5. بروتوكولات الفحص الشبكي غير المتزامنة (Async Network Protocols)
# ==============================================================================

class AsyncProtocolHandler:
    """الصنف الأساسي لبروتوكولات المصادقة الشبكية (يدعم SSL/TLS الاختياري)"""

    def __init__(self, use_ssl: bool = False):
        self.use_ssl = use_ssl
        self._ssl_ctx = ssl.create_default_context() if use_ssl else None

    async def _open(self, host: str, port: int, timeout: float) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """فتح اتصال خام مع تغليف SSL/TLS تلقائي عند الحاجة"""
        if self._ssl_ctx is not None:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self._ssl_ctx),
                timeout=timeout
            )
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

    async def authenticate(self, host: str, port: int, user: str, password: str, timeout: float) -> bool:
        raise NotImplementedError


class AsyncHTTPBasicHandler(AsyncProtocolHandler):
    """مصادقة HTTP Basic عبر المقابس الخام (Raw Async Stream)"""

    def __init__(self, path: str = "/", use_ssl: bool = False):
        super().__init__(use_ssl=use_ssl)
        self.path = path if path.startswith("/") else f"/{path}"

    async def authenticate(self, host: str, port: int, user: str, password: str, timeout: float) -> bool:
        try:
            reader, writer = await self._open(host, port, timeout)

            raw_creds = f"{user}:{password}".encode("utf-8")
            b64_creds = base64.b64encode(raw_creds).decode("utf-8")

            http_request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Basic {b64_creds}\r\n"
                f"User-Agent: Mozilla/5.0 ({__tool_name__}/{__version__})\r\n"
                f"Connection: close\r\n\r\n"
            )

            writer.write(http_request.encode("utf-8"))
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            await _close_writer(writer)

            line_str = status_line.decode("utf-8", errors="ignore")
            # نجاح الدخول عند عدم استلام كود 401 Unauthorized
            if " 200 " in line_str or " 301 " in line_str or " 302 " in line_str:
                return True
            return False
        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError,
                BrokenPipeError, ssl.SSLError, OSError):
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False


class AsyncHTTPPostHandler(AsyncProtocolHandler):
    """مصادقة نماذج تسجيل الدخول عبر HTTP POST (CSRF + كوكيز + تحليل تفاضلي)

    آلية العمل لكل محاولة:
      1. طلب GET أولي لصفحة النموذج لجمع Set-Cookie وحقول input hidden (مثل CSRF).
      2. إرسال POST بترميز application/x-www-form-urlencoded يتضمن الحقول
         المخفية + اسم المستخدم وكلمة المرور، مع ترويسة Cookie.
      3. تحليل تفاضلي للاستجابة لتحديد النجاح (انظر _evaluate).
    """

    def __init__(self, path: str = "/login", user_field: str = "username",
                 pass_field: str = "password", fail_string: Optional[str] = None,
                 success_code: Optional[int] = None, csrf_field: Optional[str] = None,
                 use_ssl: bool = False):
        super().__init__(use_ssl=use_ssl)
        self.path = path if path.startswith("/") else f"/{path}"
        self.user_field = user_field
        self.pass_field = pass_field
        self.fail_string = fail_string
        self.success_code = success_code
        self.csrf_field = csrf_field

    async def _fetch_login_page(self, host: str, port: int, timeout: float) -> Tuple[List[str], bytes]:
        """GET لصفحة النموذج وإرجاع (قائمة Set-Cookie, جسم الصفحة)"""
        reader, writer = await self._open(host, port, timeout)
        try:
            request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Mozilla/5.0 ({__tool_name__}/{__version__})\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("utf-8"))
            await writer.drain()
            _, _, set_cookies, body = await _read_http_response(reader, timeout)
            return set_cookies, body
        finally:
            await _close_writer(writer)

    def _evaluate(self, status_code: int, body_text: str) -> bool:
        """التحليل التفاضلي: تحديد نجاح المصادقة بناءً على المعايير المحددة"""
        if self.success_code is not None:
            return status_code == self.success_code
        # إعادة التوجيه (302/303...) مؤشر افتراضي على نجاح تسجيل الدخول
        if status_code in (301, 302, 303, 307, 308):
            return True
        if self.fail_string is not None:
            # النجاح = عدم وجود نص الفشل في الاستجابة
            return self.fail_string not in body_text
        return False

    async def authenticate(self, host: str, port: int, user: str, password: str, timeout: float) -> bool:
        try:
            # 1) جلب صفحة النموذج: كوكيز الجلسة + رمز CSRF المخفي
            set_cookies, page_body = await self._fetch_login_page(host, port, timeout)
            cookie_header = _build_cookie_header(set_cookies)
            page_text = page_body.decode("utf-8", errors="ignore")
            hidden = _extract_hidden_fields(page_text, wanted_field=self.csrf_field)

            # 2) بناء جسم النموذج بترميز x-www-form-urlencoded
            fields: Dict[str, str] = dict(hidden)
            fields[self.user_field] = user
            fields[self.pass_field] = password
            body_bytes = urllib.parse.urlencode(fields).encode("utf-8")

            scheme = "https" if self.use_ssl else "http"
            request = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Mozilla/5.0 ({__tool_name__}/{__version__})\r\n"
                "Accept: text/html\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Referer: {scheme}://{host}:{port}{self.path}\r\n"
            )
            if cookie_header:
                request += f"Cookie: {cookie_header}\r\n"
            request += "Connection: close\r\n\r\n"

            # 3) إرسال POST وقراءة الاستجابة كاملة
            reader, writer = await self._open(host, port, timeout)
            try:
                writer.write(request.encode("utf-8") + body_bytes)
                await writer.drain()
                status_code, _, _, resp_body = await _read_http_response(reader, timeout)
            finally:
                await _close_writer(writer)

            body_text = resp_body.decode("utf-8", errors="ignore")
            return self._evaluate(status_code, body_text)

        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError,
                BrokenPipeError, ssl.SSLError, OSError):
            return False
        except asyncio.CancelledError:
            raise  # إعادة إلغاء المهمة بأمان دون ابتلاعها
        except Exception:
            return False


class AsyncFTPHandler(AsyncProtocolHandler):
    """مصادقة بروتوكول FTP عبر المقابس غير المتزامنة (RFC 959)"""

    async def authenticate(self, host: str, port: int, user: str, password: str, timeout: float) -> bool:
        try:
            reader, writer = await self._open(host, port, timeout)

            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not banner.startswith(b"220"):
                await _close_writer(writer)
                return False

            writer.write(f"USER {user}\r\n".encode("utf-8"))
            await writer.drain()
            _ = await asyncio.wait_for(reader.readline(), timeout=timeout)

            writer.write(f"PASS {password}\r\n".encode("utf-8"))
            await writer.drain()
            pass_resp = await asyncio.wait_for(reader.readline(), timeout=timeout)

            writer.write(b"QUIT\r\n")
            await writer.drain()
            await _close_writer(writer)

            # كود 230 يمثل تسجيل الدخول بنجاح
            return pass_resp.startswith(b"230")
        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError,
                BrokenPipeError, ssl.SSLError, OSError):
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False


class AsyncSMTPHandler(AsyncProtocolHandler):
    """مصادقة بروتوكول البريد SMTP AUTH LOGIN (RFC 4954)"""

    async def authenticate(self, host: str, port: int, user: str, password: str, timeout: float) -> bool:
        try:
            reader, writer = await self._open(host, port, timeout)

            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not banner.startswith(b"220"):
                await _close_writer(writer)
                return False

            writer.write(b"EHLO audit.local\r\n")
            await writer.drain()

            # قراءة جميع أسطر استجابة الـ EHLO
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if line[3:4] == b" ":
                    break

            writer.write(b"AUTH LOGIN\r\n")
            await writer.drain()
            auth_prompt = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not auth_prompt.startswith(b"334"):
                await _close_writer(writer)
                return False

            # إرسال اسم المستخدم بصيغة Base64
            user_b64 = base64.b64encode(user.encode("utf-8")).decode("utf-8")
            writer.write(f"{user_b64}\r\n".encode("utf-8"))
            await writer.drain()
            _ = await asyncio.wait_for(reader.readline(), timeout=timeout)

            # إرسال كلمة المرور بصيغة Base64
            pass_b64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")
            writer.write(f"{pass_b64}\r\n".encode("utf-8"))
            await writer.drain()
            auth_res = await asyncio.wait_for(reader.readline(), timeout=timeout)

            writer.write(b"QUIT\r\n")
            await writer.drain()
            await _close_writer(writer)

            # كود 235 يمثل اكتمال المصادقة بنجاح
            return auth_res.startswith(b"235")
        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError,
                BrokenPipeError, ssl.SSLError, OSError):
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False


# ==============================================================================
# 6. محرك الأوركسترا والإحصائيات الحية (Async Orchestrator Engine)
# ==============================================================================

class AsyncAuditOrchestrator:
    """إدارة التزامن الفائق، شريط الإحصائيات، وإدارة مقاطعة الجلسات"""

    def __init__(self, handler: AsyncProtocolHandler, host: str, port: int, concurrency: int, timeout: float, logger: logging.Logger):
        self.handler = handler
        self.host = host
        self.port = port
        self.concurrency = concurrency
        self.timeout = timeout
        self.logger = logger
        self.semaphore = asyncio.Semaphore(concurrency)
        self.found_credentials: List[Tuple[str, str]] = []
        self.total_pairs: List[Tuple[str, str]] = []
        self.processed_count = 0
        self.start_index = 0
        self.stop_on_found = False
        self.interrupted = False

    async def _worker(self, index: int, user: str, passw: str):
        if self.stop_on_found and self.found_credentials:
            return
        if self.interrupted:
            return

        async with self.semaphore:
            if self.interrupted:
                return
            self.processed_count += 1
            try:
                is_valid = await self.handler.authenticate(self.host, self.port, user, passw, self.timeout)
            except asyncio.CancelledError:
                raise  # السيمانفور يُحرَّر تلقائياً عبر مدير السياق
            except Exception:
                return

            if is_valid:
                print(f"\r" + " " * 80 + "\r", end="")  # مسح سطر الإحصائيات
                print(UI.color(f"[+] [SUCCESS] Identified: [{user}:{passw}] on {self.host}:{self.port}", UI.GREEN))
                self.found_credentials.append((user, passw))

    async def _live_reporter(self, total: int, start_time: float):
        """تحديث حي لمعدل الطلبات في الثانية ونسبة الإنجاز"""
        try:
            while self.processed_count < total and not self.interrupted:
                if self.stop_on_found and self.found_credentials:
                    break

                elapsed = time.time() - start_time
                rate = self.processed_count / elapsed if elapsed > 0 else 0
                pct = (self.processed_count / total) * 100 if total > 0 else 0

                sys.stdout.write(
                    f"\r{UI.CYAN}[*] Progress: {self.processed_count}/{total} ({pct:.1f}%) | "
                    f"Rate: {rate:.1f} req/s | Recovered: {len(self.found_credentials)}{UI.RESET}"
                )
                sys.stdout.flush()
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass
        finally:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()

    def save_state(self, protocol_name: str) -> None:
        """حفظ نقطة التوقف بشكل متزامن - آمن للاستدعاء أثناء/بعد الإلغاء"""
        CheckpointManager.save_checkpoint(
            self.host, protocol_name,
            self.start_index + self.processed_count,
            self.found_credentials
        )

    async def run(self, pairs: List[Tuple[str, str]], start_index: int = 0, stop_on_found: bool = False, protocol_name: str = "") -> List[Tuple[str, str]]:
        self.total_pairs = pairs
        self.start_index = start_index
        self.stop_on_found = stop_on_found

        total_to_run = len(pairs) - start_index
        self.logger.info(f"Dispatching {total_to_run} candidate pairs (Concurrency: {self.concurrency})")

        start_time = time.time()
        reporter_task = asyncio.create_task(self._live_reporter(total_to_run, start_time))

        tasks = []
        for i in range(start_index, len(pairs)):
            u, p = pairs[i]
            tasks.append(self._worker(i, u, p))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            # المهمة أُلغيت من الخارج (Ctrl+C): نُعلم العلم ونكمل التنظيف دون ابتلاع الإلغاء
            self.interrupted = True
        finally:
            reporter_task.cancel()
            try:
                await reporter_task
            except (asyncio.CancelledError, Exception):
                pass

        elapsed = time.time() - start_time
        speed = self.processed_count / elapsed if elapsed > 0 else 0

        # إذا تمت المقاطعة نحفظ نقطة التوقف (عملية متزامنة - لا تتطلب Loop)
        if self.interrupted:
            self.save_state(protocol_name)
            print(UI.color("\n[!] Session state checkpointed. Resume anytime with --resume", UI.YELLOW))
        else:
            CheckpointManager.clear_checkpoint(self.host, protocol_name)

        print("\n" + "=" * 70)
        print(f"Summary: Execution completed in {elapsed:.2f}s | Average Speed: {speed:.2f} req/s")
        print(f"Total Valid Accounts Identified: {len(self.found_credentials)}")
        print("=" * 70)

        return self.found_credentials


# ==============================================================================
# 7. مساعدات قراءة الملفات والإعدادات (File & Configuration Parsers)
# ==============================================================================

def read_list_file(filepath: str) -> List[str]:
    """قراءة القواميس مع معالجة الأخطاء دون ظهور Traceback"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Specified wordlist does not exist: {filepath}")
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        raise OSError(f"Failed to access file '{filepath}': {str(e)}")


def parse_config_file(filepath: str) -> Dict[str, Any]:
    """قراءة ملف إعدادات JSON والتحقق من صحته"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Configuration file not found: {filepath}")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise ValueError(f"Corrupted or invalid JSON in config: {str(e)}")


# ==============================================================================
# 8. واجهة سطر الأوامر ونقطة الدخول (CLI & Subcommands Engine)
# ==============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="HydraBrute",
        description="High-Throughput Asynchronous Network Authentication Tester (Pure Python).",
        epilog="Academic Adversary Emulation & Assessment Framework (Pure Standard Library)."
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s v{__version__}")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Control logging verbosity.")
    parser.add_argument("--config", type=str, default=None, help="Path to JSON configuration file.")

    subparsers = parser.add_subparsers(dest="protocol", help="Protocol module to execute")

    # 1. أمر HTTP-Basic
    http_p = subparsers.add_parser("http-basic", help="Audit HTTP Basic Authentication endpoint.")
    http_p.add_argument("-t", "--target", required=True, help="Target host/IP or URL (http(s):// and trailing slashes are auto-stripped).")
    http_p.add_argument("-p", "--port", type=int, default=80, help="Port number (default: 80).")
    http_p.add_argument("--path", type=str, default="/", help="URI path (default: /).")
    http_p.add_argument("--ssl", action="store_true", help="Force SSL/TLS wrapping for the connection.")
    _append_common_arguments(http_p)

    # 2. أمر HTTP-POST (نماذج تسجيل الدخول)
    http_post_p = subparsers.add_parser("http-post", help="Audit web form login (HTTP POST with CSRF tokens & session cookies).")
    http_post_p.add_argument("-t", "--target", required=True, help="Target host/IP or URL (http(s):// and trailing slashes are auto-stripped).")
    http_post_p.add_argument("-p", "--port", type=int, default=80, help="Port number (default: 80, 443 implies SSL).")
    http_post_p.add_argument("--path", type=str, default="/login", help="Login form URI path (default: /login).")
    http_post_p.add_argument("--user-field", type=str, default="username", help="Form field name for the username (default: username).")
    http_post_p.add_argument("--pass-field", type=str, default="password", help="Form field name for the password (default: password).")
    http_post_p.add_argument("--fail-string", type=str, default=None, help="Mark attempt SUCCESSFUL if this string is ABSENT in the response body (e.g. 'Invalid username or password').")
    http_post_p.add_argument("--success-code", type=int, default=None, help="Mark attempt SUCCESSFUL if the HTTP status code matches (e.g. 302).")
    http_post_p.add_argument("--csrf-field", type=str, default=None, help="Extract only this hidden input field (default: all hidden inputs are submitted).")
    http_post_p.add_argument("--ssl", action="store_true", help="Force SSL/TLS wrapping for the connection.")
    _append_common_arguments(http_post_p)

    # 3. أمر FTP
    ftp_p = subparsers.add_parser("ftp", help="Audit FTP Authentication service.")
    ftp_p.add_argument("-t", "--target", required=True, help="Target host/IP.")
    ftp_p.add_argument("-p", "--port", type=int, default=21, help="Port number (default: 21).")
    _append_common_arguments(ftp_p)

    # 4. أمر SMTP
    smtp_p = subparsers.add_parser("smtp", help="Audit SMTP AUTH LOGIN service.")
    smtp_p.add_argument("-t", "--target", required=True, help="Target host/IP.")
    smtp_p.add_argument("-p", "--port", type=int, default=25, help="Port number (default: 25).")
    _append_common_arguments(smtp_p)

    return parser


def _append_common_arguments(subp: argparse.ArgumentParser):
    """إضافة المعاملات المشتركة لجميع الأوامر الفرعية"""
    u_group = subp.add_mutually_exclusive_group(required=True)
    u_group.add_argument("-u", "--username", help="Single username.")
    u_group.add_argument("-U", "--userlist", help="Path to user wordlist.")

    p_group = subp.add_mutually_exclusive_group(required=True)
    p_group.add_argument("-w", "--password", help="Single password.")
    p_group.add_argument("-P", "--passlist", help="Path to password wordlist.")

    subp.add_argument("-c", "--concurrency", type=int, default=32, help="Concurrency limit (default: 32).")
    subp.add_argument("--timeout", type=float, default=2.5, help="Network timeout in seconds (default: 2.5).")
    subp.add_argument("-F", "--stop-on-found", action="store_true", help="Halt execution on first recovered credential.")
    subp.add_argument("--mutate", action="store_true", help="Enable in-memory dynamic rule-based password mutations.")
    subp.add_argument("--resume", action="store_true", help="Resume from previous checkpoint if available.")
    subp.add_argument("--export", type=str, help="Save verified credentials to JSON report.")


def main():
    UI.setup()
    parser = create_argument_parser()
    args = parser.parse_args()

    logger = setup_logger(args.log_level)

    if not args.protocol:
        parser.print_help()
        sys.exit(0)

    try:
        if args.config:
            cfg = parse_config_file(args.config)
            logger.info(f"Loaded parameters from configuration file: {args.config}")

        # تعقيم الهدف: إزالة المخطط والشرطات، وكشف SSL تلقائياً من 443/https
        clean_host, inferred_port, scheme_https = sanitize_target(args.target)
        args.target = clean_host
        if inferred_port is not None and inferred_port != args.port:
            args.port = inferred_port
            logger.info(f"Port inferred from target URL: {args.port}")
        use_ssl = scheme_https or (args.port == 443) or bool(getattr(args, "ssl", False))

        # تجهيز قوائم أسماء المستخدمين
        usernames = [args.username] if args.username else read_list_file(args.userlist)

        # تجهيز قوائم كلمات المرور مع التحوير إذا تم تفعيله
        raw_passwords = [args.password] if args.password else read_list_file(args.passlist)

        if args.mutate:
            logger.info("Applying dynamic in-memory rule mutations...")
            final_passwords = []
            for p in raw_passwords:
                final_passwords.extend(list(RuleMutator.mutate(p)))
            passwords = list(dict.fromkeys(final_passwords))  # إزالة التكرار مع الحفاظ على الترتيب
        else:
            passwords = raw_passwords

        # بناء جميع الأزواج
        all_pairs = [(u, p) for u in usernames for p in passwords]

        # اختيار معالج البروتوكول
        if args.protocol == "http-basic":
            handler = AsyncHTTPBasicHandler(path=args.path, use_ssl=use_ssl)
        elif args.protocol == "http-post":
            handler = AsyncHTTPPostHandler(
                path=args.path,
                user_field=args.user_field,
                pass_field=args.pass_field,
                fail_string=args.fail_string,
                success_code=args.success_code,
                csrf_field=args.csrf_field,
                use_ssl=use_ssl
            )
            if use_ssl:
                logger.info("SSL/TLS wrapping enabled for http-post connection.")
        elif args.protocol == "ftp":
            handler = AsyncFTPHandler()
        elif args.protocol == "smtp":
            handler = AsyncSMTPHandler()
        else:
            logger.error("Specified protocol is not supported.")
            sys.exit(1)

        start_index = 0
        # استئناف الجلسة السابقة
        if args.resume:
            checkpoint = CheckpointManager.load_checkpoint(args.target, args.protocol)
            if checkpoint:
                start_index = checkpoint.get("completed_index", 0)
                logger.info(f"Resuming session for {args.target} from index: {start_index}")

        print(UI.color(f"\n[*] Initializing {__tool_name__} v{__version__} against {args.target}:{args.port} [{args.protocol.upper()}]", UI.BOLD))

        orchestrator = AsyncAuditOrchestrator(
            handler=handler,
            host=args.target,
            port=args.port,
            concurrency=args.concurrency,
            timeout=args.timeout,
            logger=logger
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # إنشاء المهمة صراحةً للإمساك بها عند KeyboardInterrupt
        audit_task = loop.create_task(
            orchestrator.run(all_pairs, start_index=start_index, stop_on_found=args.stop_on_found, protocol_name=args.protocol)
        )

        try:
            results = loop.run_until_complete(audit_task)
        except KeyboardInterrupt:
            orchestrator.interrupted = True
            audit_task.cancel()
            # إلغاء كل المهام المتبقية بأمان وانتظارها دون تسريب استثناءات
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            # مهمّة الـ run نفسها تُكمل حفظ نقطة التوقف داخلياً قبل إنهائها
            loop.run_until_complete(asyncio.gather(audit_task, return_exceptions=True))
            results = orchestrator.found_credentials
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()

        # تصدير التقرير
        if args.export:
            report_data = {
                "engine": __tool_name__,
                "version": __version__,
                "target": args.target,
                "port": args.port,
                "protocol": args.protocol,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "results": [{"user": u, "pass": p} for u, p in results]
            }
            with open(args.export, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"Results exported successfully to: {args.export}")

    except (FileNotFoundError, ValueError, OSError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()