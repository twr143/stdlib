import DsnTwist.{REQUEST_TIMEOUT_HTTP, VALID_FQDN_REGEX}

import java.util.regex.Pattern
import java.time.{LocalDateTime, ZonedDateTime}
import java.time.format.DateTimeFormatter
import java.net.{InetSocketAddress, Socket}
import javax.net.ssl.{HttpsURLConnection, SSLContext}
import java.io.{BufferedReader, InputStreamReader}
import java.net.{HttpURLConnection, URL}
import java.util.zip.GZIPInputStream
import scala.collection.JavaConverters._
import scala.util.matching.Regex
import scala.collection.mutable

object DsnTwist {
  val VALID_FQDN_REGEX = Pattern.compile("(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\\.)+[a-z0-9-]{2,63}$)", Pattern.CASE_INSENSITIVE)
  val USER_AGENT_STRING = s"Mozilla/5.0 (${sys.props("os.name")} ${sys.props("os.arch")}) dnstwist/${/*__version__*/}"

  val REQUEST_TIMEOUT_DNS = 2.5
  val REQUEST_RETRIES_DNS = 2
  val REQUEST_TIMEOUT_HTTP = 5
  val REQUEST_TIMEOUT_SMTP = 5
  val THREAD_COUNT_DEFAULT = math.min(32, Runtime.getRuntime.availableProcessors + 4)

//  val (FG_RND, FG_YEL, FG_CYA, FG_BLU, FG_RST, ST_BRI, ST_CLR, ST_RST) =
//    if (sys.props("os.name") != "Windows" && System.console() != null) {
//      (s"\u001b[3${(System.currentTimeMillis % 8 + 1).toInt}m", "\u001b[33m", "\u001b[36m", "\u001b[34m", "\u001b[39m", "\u001b[1m", "\u001b[1K", "\u001b[0m")
//    } else {
//      ("", "", "", "", "", "", "", "")
//    }

  val devnull = "/dev/null"

  def domainTld(domain: String): (String, String, String) = {
   val ctld = Set("org", "com", "net", "gov", "edu", "co", "mil", "nom", "ac", "info", "biz", "ru")
        val d = domain.split("\\.").reverse
        d.length match {
          case 1 => ("", d(0), "")
          case 2 => ("", d(1), d(0))
          case _ if ctld.contains(d(1)) => (d.drop(3).reverse.mkString("."), d(2), d.take(2).reverse.mkString("."))
          case _ => (d.drop(2).reverse.mkString("."), d(1), d(0))
        }

  }

}
class Whois {
  val WHOIS_IANA = "whois.iana.org"
  val TIMEOUT = 2.0
  val WHOIS_TLD = mutable.Map(
    "com" -> "whois.verisign-grs.com",
    "net" -> "whois.verisign-grs.com",
    "org" -> "whois.pir.org",
    "info" -> "whois.afilias.net",
    "pl" -> "whois.dns.pl",
    "us" -> "whois.nic.us",
    "co" -> "whois.nic.co",
    "cn" -> "whois.cnnic.cn",
    "ru" -> "whois.tcinet.ru",
    "in" -> "whois.registry.in"
  )

  private def bruteDatetime(s: String): Option[LocalDateTime] = {
    val formats = List(
      "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd HH:mm:ssX", "yyyy-MM-dd HH:mm", "yyyy.MM.dd HH:mm",
      "yyyy.MM.dd HH:mm:ss", "dd.MM.yyyy HH:mm:ss", "EEE MMM dd yyyy", "dd-MMM-yyyy", "yyyy-MM-dd"
    )
    formats.flatMap { format =>
      try {
        Some(LocalDateTime.parse(s, DateTimeFormatter.ofPattern(format)))
      } catch {
        case _: Exception => None
      }
    }.headOption
  }

  private def extract(response: String): Map[String, Any] = {
    val fields = Map(
      "registrar" -> """(?i)[\r\n]registrar[ .]*:\s+(?:name:\s)?(?<registrar>[^\r\n]+)""".r,
      "creation_date" -> """(?i)[\r\n](?:created(?: on)?|creation date|registered(?: on)?)[ .]*:\s+(?<creation_date>[^\r\n]+)""".r
    )

    val result = mutable.Map("text" -> response)
    val responseReduced = response.split("\r\n").filterNot(_.startsWith("%")).map(_.trim).mkString("\r\n")

    fields.foreach { case (field, pattern) =>
      pattern.findFirstMatchIn(responseReduced).foreach { m =>
        result(field) = m.group(1)
      }
    }

    result.toMap
  }

  def query(q: String, server: Option[String] = None): String = {
    val (_, _, tld) = DsnTwist.domainTld(q)
    val whoisServer = server.getOrElse(WHOIS_TLD.getOrElse(tld, WHOIS_IANA))

    val socket = new Socket()
    try {
      socket.connect(new InetSocketAddress(whoisServer, 43), (TIMEOUT * 1000).toInt)
      val out = new java.io.PrintWriter(socket.getOutputStream, true)
      val in = new BufferedReader(new InputStreamReader(socket.getInputStream))

      out.println(q)
      val response = new StringBuilder
      var line: String = null
      while ( {
        line = in.readLine; line != null
      }) {
        response.append(line).append("\n")
      }

      val responseStr = response.toString
      if (server.isEmpty && whoisServer != WHOIS_IANA && !WHOIS_TLD.contains(tld)) {
        WHOIS_TLD(tld) = whoisServer
      }

      val referPattern = """(?i)refer:\s+(?<server>\w[-.\w]+)""".r
      referPattern.findFirstMatchIn(responseStr) match {
        case Some(m) => query(q, Some(m.group("server")))
        case None => responseStr
      }
    } finally {
      socket.close()
    }
  }

  def whois(domain: String, server: Option[String] = None): Map[String, Any] = {
    extract(query(domain, server))
  }
}

class UrlOpener(url: String, timeout: Int = REQUEST_TIMEOUT_HTTP, hders: Map[String, String] = Map.empty, verify: Boolean = true) {
  private val httpHeaders = mutable.Map(
    "accept" -> "text/html,application/xhtml+xml,application/xml;q=0.9",
    "accept-encoding" -> "gzip,identity",
    "accept-language" -> "en-GB,en-US;q=0.9,en;q=0.8"
  )
  httpHeaders ++= hders.filter(_._1.toLowerCase != "accept-encoding")

  private val connection = new URL(url).openConnection().asInstanceOf[HttpsURLConnection]
  connection.setRequestMethod("GET")
  httpHeaders.foreach { case (key, value) => connection.setRequestProperty(key, value) }
  connection.setConnectTimeout(timeout * 1000)
  connection.setReadTimeout(timeout * 1000)

  if (!verify) {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, Array(new javax.net.ssl.X509TrustManager {
      def getAcceptedIssuers = null

      def checkClientTrusted(certs: Array[java.security.cert.X509Certificate], authType: String) = ()

      def checkServerTrusted(certs: Array[java.security.cert.X509Certificate], authType: String) = ()
    }), new java.security.SecureRandom())
    connection.setSSLSocketFactory(sslContext.getSocketFactory)
  }

  connection.connect()

  val headers = connection.getHeaderFields.asScala.map { case (k, v) => k -> v.asScala.mkString(",") }.toMap
  val code = connection.getResponseCode
  val reason = connection.getResponseMessage

  val inputStream = if (connection.getContentEncoding == "gzip") new GZIPInputStream(connection.getInputStream) else connection.getInputStream
  val content = scala.io.Source.fromInputStream(inputStream).mkString

  val normalizedContent = {
    val contentBytes = content.getBytes
    val normalized = contentBytes.grouped(2).flatMap {
      case Array(b1, b2) if b1 == ' '.toByte => Array(b1)
      case other => other
    }.toArray
    new String(normalized)
  }

  if (64 < content.length && content.length < 1024) {
    val metaUrlPattern = """(?i)<meta[^>]*?url=(https?://\w.,?!:;/*#@$&+=[]()%~-]*?)"""".r
    metaUrlPattern.findFirstMatchIn(content) match {
      case Some(m) => new UrlOpener(m.group(1), timeout, httpHeaders.toMap, verify)
      case None =>
    }
  }
}

class UrlParser(url: String) {
  if (url.isEmpty) throw new IllegalArgumentException("argument has to be non-empty string")

  private val parsedUrl = new URL(if (url.contains("://")) url else s"http://$url")
  val scheme = parsedUrl.getProtocol.toLowerCase
  if (scheme != "http" && scheme != "https") throw new IllegalArgumentException("invalid scheme")

  val domain = parsedUrl.getHost.toLowerCase
  if (!validateDomain(domain)) throw new IllegalArgumentException("invalid domain name")

  val username = Option(parsedUrl.getUserInfo).map(_.split(":").head).orNull
  val password = Option(parsedUrl.getUserInfo).flatMap(_.split(":").tail.headOption).orNull
  val port = if (parsedUrl.getPort == -1) None else Some(parsedUrl.getPort)
  val path = parsedUrl.getPath
  val query = parsedUrl.getQuery
  val fragment = parsedUrl.getRef

  private def validateDomain(domain: String): Boolean = {
    if (domain.length < 1 || domain.length > 253) return false
    VALID_FQDN_REGEX.matcher(domain).matches()
  }

  def fullUri(domain: Option[String] = None): String = {
    val sb = new StringBuilder(s"$scheme://")
    if (username != null) {
      sb.append(username)
      if (password != null) sb.append(s":$password")
      sb.append("@")
    }
    sb.append(domain.getOrElse(this.domain))
    port.foreach(p => sb.append(s":$p"))
    if (path != null) sb.append(path)
    if (query != null) sb.append(s"?$query")
    if (fragment != null) sb.append(s"#$fragment")
    sb.toString
  }
}

case class Permutation(fuzzer: String = "", domain: String = "", attributes: Map[String, Any] = Map.empty) {
  def isRegistered: Boolean = attributes.nonEmpty

  def copy(newFuzzer: String = fuzzer, newDomain: String = domain, newAttributes: Map[String, Any] = attributes): Permutation =
    Permutation(newFuzzer, newDomain, newAttributes)
}

object Permutation {
  implicit val permutationOrdering: Ordering[Permutation] = Ordering.fromLessThan { (a, b) =>
    if (a.fuzzer == b.fuzzer) {
      if (a.attributes.nonEmpty && b.attributes.nonEmpty) {
        (a.attributes.getOrElse("dns_a", Seq("")).asInstanceOf[Seq[String]].headOption.getOrElse("") + a.domain) <
          (b.attributes.getOrElse("dns_a", Seq("")).asInstanceOf[Seq[String]].headOption.getOrElse("") + b.domain)
      } else {
        a.domain < b.domain
      }
    } else {
      a.fuzzer < b.fuzzer
    }
  }
}

import scala.collection.mutable

class Fuzzer(dom: String, dictionary: Seq[String] = Seq(), var tldDictionary: Seq[String] = Seq()) {
  val glyphsIdnByTld: Map[String, Map[String, Seq[String]]] = Map(
    "ad" -> Map(),
    "cz" -> Map(),
    "sk" -> Map(),
    "uk" -> Map(),
    "co.uk" -> Map(),
    "nl" -> Map(),
    "edu" -> Map(),
    "us" -> Map(),
    "jp" -> Map(),
    "co.jp" -> Map(),
    "ad.jp" -> Map(),
    "ne.jp" -> Map(),
    "cn" -> Map(),
    "com.cn" -> Map(),
    "tw" -> Map(),
    "com.tw" -> Map(),
    "net.tw" -> Map(),
    "info" -> Map(
      "a" -> Seq("á", "ä", "å", "ą"),
      "c" -> Seq("ć", "č"),
      "e" -> Seq("é", "ė", "ę"),
      "i" -> Seq("í", "į"),
      "l" -> Seq("ł"),
      "n" -> Seq("ñ", "ń"),
      "o" -> Seq("ó", "ö", "ø", "ő"),
      "s" -> Seq("ś", "š"),
      "u" -> Seq("ú", "ü", "ū", "ű", "ų"),
      "z" -> Seq("ź", "ż", "ž"),
      "ae" -> Seq("æ")
    ),
    "br" -> Map(
      "a" -> Seq("à", "á", "â", "ã"),
      "c" -> Seq("ç"),
      "e" -> Seq("é", "ê"),
      "i" -> Seq("í"),
      "o" -> Seq("ó", "ô", "õ"),
      "u" -> Seq("ú", "ü"),
      "y" -> Seq("ý", "ÿ")
    ),
    "dk" -> Map(
      "a" -> Seq("ä", "å"),
      "e" -> Seq("é"),
      "o" -> Seq("ö", "ø"),
      "u" -> Seq("ü"),
      "ae" -> Seq("æ")
    ),
    "eu" -> Map(
      "a" -> Seq("á", "à", "ă", "â", "å", "ä", "ã", "ą", "ā"),
      "c" -> Seq("ć", "ĉ", "č", "ċ", "ç"),
      "d" -> Seq("ď", "đ"),
      "e" -> Seq("é", "è", "ĕ", "ê", "ě", "ë", "ė", "ę", "ē"),
      "g" -> Seq("ğ", "ĝ", "ġ", "ģ"),
      "h" -> Seq("ĥ", "ħ"),
      "i" -> Seq("í", "ì", "ĭ", "î", "ï", "ĩ", "į", "ī"),
      "j" -> Seq("ĵ"),
      "k" -> Seq("ķ", "ĸ"),
      "l" -> Seq("ĺ", "ľ", "ļ", "ł"),
      "n" -> Seq("ń", "ň", "ñ", "ņ"),
      "o" -> Seq("ó", "ò", "ŏ", "ô", "ö", "ő", "õ", "ø", "ō"),
      "r" -> Seq("ŕ", "ř", "ŗ"),
      "s" -> Seq("ś", "ŝ", "š", "ş"),
      "t" -> Seq("ť", "ţ", "ŧ"),
      "u" -> Seq("ú", "ù", "ŭ", "û", "ů", "ü", "ű", "ũ", "ų", "ū"),
      "w" -> Seq("ŵ"),
      "y" -> Seq("ý", "ŷ", "ÿ"),
      "z" -> Seq("ź", "ž", "ż"),
      "ae" -> Seq("æ"),
      "oe" -> Seq("œ")
    ),
    "fi" -> Map(
      "3" -> Seq("ʒ"),
      "a" -> Seq("á", "ä", "å", "â"),
      "c" -> Seq("č"),
      "d" -> Seq("đ"),
      "g" -> Seq("ǧ", "ǥ"),
      "k" -> Seq("ǩ"),
      "n" -> Seq("ŋ"),
      "o" -> Seq("õ", "ö"),
      "s" -> Seq("š"),
      "t" -> Seq("ŧ"),
      "z" -> Seq("ž")
    ),
    "no" -> Map(
      "a" -> Seq("á", "à", "ä", "å"),
      "c" -> Seq("č", "ç"),
      "e" -> Seq("é", "è", "ê"),
      "i" -> Seq("ï"),
      "n" -> Seq("ŋ", "ń", "ñ"),
      "o" -> Seq("ó", "ò", "ô", "ö", "ø"),
      "s" -> Seq("š"),
      "t" -> Seq("ŧ"),
      "u" -> Seq("ü"),
      "z" -> Seq("ž"),
      "ae" -> Seq("æ")
    ),
    "be" -> Map(
      "a" -> Seq("à", "á", "â", "ã", "ä", "å"),
      "c" -> Seq("ç"),
      "e" -> Seq("è", "é", "ê", "ë"),
      "i" -> Seq("ì", "í", "î", "ï"),
      "n" -> Seq("ñ"),
      "o" -> Seq("ò", "ó", "ô", "õ", "ö"),
      "u" -> Seq("ù", "ú", "û", "ü"),
      "y" -> Seq("ý", "ÿ"),
      "ae" -> Seq("æ"),
      "oe" -> Seq("œ")
    ),
    "fr" -> Map(
      "a" -> Seq("à", "â", "ã", "ä", "å"),
      "c" -> Seq("ç"),
      "e" -> Seq("è", "é", "ê", "ë"),
      "i" -> Seq("ì", "í", "î", "ï"),
      "n" -> Seq("ñ"),
      "o" -> Seq("ò", "ó", "ô", "õ", "ö"),
      "u" -> Seq("ù", "ú", "û", "ü"),
      "y" -> Seq("ý", "ÿ"),
      "ae" -> Seq("æ"),
      "oe" -> Seq("œ")
    ),
    "ca" -> Map(
      "a" -> Seq("à", "â"),
      "c" -> Seq("ç"),
      "e" -> Seq("è", "é", "ê", "ë"),
      "i" -> Seq("î", "ï"),
      "o" -> Seq("ô"),
      "u" -> Seq("ù", "û", "ü"),
      "y" -> Seq("ÿ"),
      "ae" -> Seq("æ"),
      "oe" -> Seq("œ")
    )
  )

  val glyphsUnicode: Map[String, Seq[String]] = Map(
    "2" -> Seq("ƻ"),
    "3" -> Seq("ʒ"),
    "5" -> Seq("ƽ"),
    "a" -> Seq("ạ", "ă", "ȧ", "ɑ", "å", "ą", "â", "ǎ", "á", "ə", "ä", "ã", "ā", "à"),
    "b" -> Seq("ḃ", "ḅ", "ƅ", "ʙ", "ḇ", "ɓ"),
    "c" -> Seq("č", "ᴄ", "ċ", "ç", "ć", "ĉ", "ƈ"),
    "d" -> Seq("ď", "ḍ", "ḋ", "ɖ", "ḏ", "ɗ", "ḓ", "ḑ", "đ"),
    "e" -> Seq("ê", "ẹ", "ę", "è", "ḛ", "ě", "ɇ", "ė", "ĕ", "é", "ë", "ē", "ȩ"),
    "f" -> Seq("ḟ", "ƒ"),
    "g" -> Seq("ǧ", "ġ", "ǵ", "ğ", "ɡ", "ǥ", "ĝ", "ģ", "ɢ"),
    "h" -> Seq("ȟ", "ḫ", "ḩ", "ḣ", "ɦ", "ḥ", "ḧ", "ħ", "ẖ", "ⱨ", "ĥ"),
    "i" -> Seq("ɩ", "ǐ", "í", "ɪ", "ỉ", "ȋ", "ɨ", "ï", "ī", "ĩ", "ị", "î", "ı", "ĭ", "į", "ì"),
    "j" -> Seq("ǰ", "ĵ", "ʝ", "ɉ"),
    "k" -> Seq("ĸ", "ǩ", "ⱪ", "ḵ", "ķ", "ᴋ", "ḳ"),
    "l" -> Seq("ĺ", "ł", "ɫ", "ļ", "ľ"),
    "m" -> Seq("ᴍ", "ṁ", "ḿ", "ṃ", "ɱ"),
    "n" -> Seq("ņ", "ǹ", "ń", "ň", "ṅ", "ṉ", "ṇ", "ꞑ", "ñ", "ŋ"),
    "o" -> Seq("ö", "ó", "ȯ", "ỏ", "ô", "ᴏ", "ō", "ò", "ŏ", "ơ", "ő", "õ", "ọ", "ø"),
    "p" -> Seq("ṗ", "ƿ", "ƥ", "ṕ"),
    "q" -> Seq("ʠ"),
    "r" -> Seq("ʀ", "ȓ", "ɍ", "ɾ", "ř", "ṛ", "ɽ", "ȑ", "ṙ", "ŗ", "ŕ", "ɼ", "ṟ"),
    "s" -> Seq("ṡ", "ș", "ŝ", "ꜱ", "ʂ", "š", "ś", "ṣ", "ş"),
    "t" -> Seq("ť", "ƫ", "ţ", "ṭ", "ṫ", "ț", "ŧ"),
    "u" -> Seq("ᴜ", "ų", "ŭ", "ū", "ű", "ǔ", "ȕ", "ư", "ù", "ů", "ʉ", "ú", "ȗ", "ü", "û", "ũ", "ụ"),
    "v" -> Seq("ᶌ", "ṿ", "ᴠ", "ⱴ", "ⱱ", "ṽ"),
    "w" -> Seq("ᴡ", "ẇ", "ẅ", "ẃ", "ẘ", "ẉ", "ⱳ", "ŵ", "ẁ"),
    "x" -> Seq("ẋ", "ẍ"),
    "y" -> Seq("ŷ", "ÿ", "ʏ", "ẏ", "ɏ", "ƴ", "ȳ", "ý", "ỿ", "ỵ"),
    "z" -> Seq("ž", "ƶ", "ẓ", "ẕ", "ⱬ", "ᴢ", "ż", "ź", "ʐ"),
    "ae" -> Seq("æ"),
    "oe" -> Seq("œ")
  )

  val glyphsAscii: Map[String, Seq[String]] = Map(
    "0" -> Seq("o"),
    "1" -> Seq("l", "i"),
    "3" -> Seq("8"),
    "6" -> Seq("9"),
    "8" -> Seq("3"),
    "9" -> Seq("6"),
    "b" -> Seq("d", "lb"),
    "c" -> Seq("e"),
    "d" -> Seq("b", "cl", "dl"),
    "e" -> Seq("c"),
    "g" -> Seq("q"),
    "h" -> Seq("lh"),
    "i" -> Seq("1", "l"),
    "k" -> Seq("lc"),
    "l" -> Seq("1", "i"),
    "m" -> Seq("n", "nn", "rn"),
    "n" -> Seq("m", "r"),
    "o" -> Seq("0"),
    "q" -> Seq("g"),
    "w" -> Seq("vv"),
    "rn" -> Seq("m"),
    "cl" -> Seq("d")
  )

  val latinToCyrillic: Map[String, String] = Map(
    "a" -> "а", "b" -> "ь", "c" -> "с", "d" -> "ԁ", "e" -> "е", "g" -> "ԍ", "h" -> "һ",
    "i" -> "і", "j" -> "ј", "k" -> "к", "l" -> "ӏ", "m" -> "м", "o" -> "о", "p" -> "р",
    "q" -> "ԛ", "s" -> "ѕ", "t" -> "т", "v" -> "ѵ", "w" -> "ԝ", "x" -> "х", "y" -> "у"
  )

  val qwerty: Map[String, String] = Map(
    "1" -> "2q", "2" -> "3wq1", "3" -> "4ew2", "4" -> "5re3", "5" -> "6tr4", "6" -> "7yt5", "7" -> "8uy6", "8" -> "9iu7", "9" -> "0oi8", "0" -> "po9",
    "q" -> "12wa", "w" -> "3esaq2", "e" -> "4rdsw3", "r" -> "5tfde4", "t" -> "6ygfr5", "y" -> "7uhgt6", "u" -> "8ijhy7", "i" -> "9okju8", "o" -> "0plki9", "p" -> "lo0",
    "a" -> "qwsz", "s" -> "edxzaw", "d" -> "rfcxse", "f" -> "tgvcdr", "g" -> "yhbvft", "h" -> "ujnbgy", "j" -> "ikmnhu", "k" -> "olmji", "l" -> "kop",
    "z" -> "asx", "x" -> "zsdc", "c" -> "xdfv", "v" -> "cfgb", "b" -> "vghn", "n" -> "bhjm", "m" -> "njk"
  )

  val qwertz: Map[String, String] = Map(
    "1" -> "2q", "2" -> "3wq1", "3" -> "4ew2", "4" -> "5re3", "5" -> "6tr4", "6" -> "7zt5", "7" -> "8uz6", "8" -> "9iu7", "9" -> "0oi8", "0" -> "po9",
    "q" -> "12wa", "w" -> "3esaq2", "e" -> "4rdsw3", "r" -> "5tfde4", "t" -> "6zgfr5", "z" -> "7uhgt6", "u" -> "8ijhz7", "i" -> "9okju8", "o" -> "0plki9", "p" -> "lo0",
    "a" -> "qwsy", "s" -> "edxyaw", "d" -> "rfcxse", "f" -> "tgvcdr", "g" -> "zhbvft", "h" -> "ujnbgz", "j" -> "ikmnhu", "k" -> "olmji", "l" -> "kop",
    "y" -> "asx", "x" -> "ysdc", "c" -> "xdfv", "v" -> "cfgb", "b" -> "vghn", "n" -> "bhjm", "m" -> "njk"
  )

  val azerty: Map[String, String] = Map(
    "1" -> "2a", "2" -> "3za1", "3" -> "4ez2", "4" -> "5re3", "5" -> "6tr4", "6" -> "7yt5", "7" -> "8uy6", "8" -> "9iu7", "9" -> "0oi8", "0" -> "po9",
    "a" -> "2zq1", "z" -> "3esqa2", "e" -> "4rdsz3", "r" -> "5tfde4", "t" -> "6ygfr5", "y" -> "7uhgt6", "u" -> "8ijhy7", "i" -> "9okju8", "o" -> "0plki9", "p" -> "lo0m",
    "q" -> "zswa", "s" -> "edxwqz", "d" -> "rfcxse", "f" -> "tgvcdr", "g" -> "yhbvft", "h" -> "ujnbgy", "j" -> "iknhu", "k" -> "olji", "l" -> "kopm", "m" -> "lp",
    "w" -> "sxq", "x" -> "wsdc", "c" -> "xdfv", "v" -> "cfgb", "b" -> "vghn", "n" -> "bhj"
  )

  val keyboards: Seq[Map[String, String]] = Seq(qwerty, qwertz, azerty)

  private val (subdomain, domain, tld) = domainTld(dom)
  private var domains: mutable.Set[Permutation] = mutable.Set()

  private def domainTld(domain: String): (String, String, String) = {
    // Implement domain_tld logic here
    ("", "", "")
  }

  def bitsquatting(): Seq[String] = {
    val masks = Seq(1, 2, 4, 8, 16, 32, 64, 128)
    val chars = ('a' to 'z') ++ ('0' to '9') ++ Seq('-')
    for {
      (c, i) <- domain.zipWithIndex
      mask <- masks
      b = (c.toInt ^ mask).toChar
      if chars.contains(b)
    } yield domain.take(i) + b + domain.drop(i + 1)
  }

  def cyrillic(): Seq[String] = {
    var cdomain = domain
    for ((l, c) <- latinToCyrillic) {
      cdomain = cdomain.replace(l, c)
    }
    if (cdomain == domain) Seq() else Seq(cdomain)
  }

  def homoglyph(): Set[String] = {
    val md = (a: Map[String, Seq[String]], b: Map[String, Seq[String]]) => {
      (a.keySet ++ b.keySet).map { k =>
        k -> (a.getOrElse(k, Seq()) ++ b.getOrElse(k, Seq()))
      }.toMap
    }
    val glyphs = md(glyphsAscii, glyphsIdnByTld.getOrElse(tld, glyphsUnicode))
    def mix(domain: String): Seq[String] = {
      for {
        (c, i) <- domain.zipWithIndex
        g <- glyphs.getOrElse(c.toString, Seq())
      } yield domain.take(i) + g + domain.drop(i + 1)
    }
    val result1 = mix(domain).toSet
    val result2 = result1.flatMap(mix)
    result1 ++ result2
  }

  def hyphenation(): Set[String] = {
    (1 until domain.length).map(i => domain.take(i) + "-" + domain.drop(i)).toSet
  }

  def insertion(): Set[String] = {
    val result = mutable.Set[String]()
    for (i <- 0 until domain.length - 1) {
      val (prefix, origC, suffix) = (domain.take(i), domain(i), domain.drop(i + 1))
      for {
        c <- keyboards.flatMap(_.get(origC.toString).toSeq.flatten)
      } {
        result.add(prefix + c + origC + suffix)
        result.add(prefix + origC + c + suffix)
      }
    }
    result.toSet
  }

  def omission(): Set[String] = {
    (0 until domain.length).map(i => domain.take(i) + domain.drop(i + 1)).toSet
  }

  def repetition(): Set[String] = {
    (0 until domain.length).map(i => domain.take(i) + domain(i) + domain.drop(i)).toSet
  }

  def replacement(): Seq[String] = {
    for {
      (c, i) <- domain.zipWithIndex
      pre = domain.take(i)
      suf = domain.drop(i + 1)
      layout <- keyboards
      r <- layout.get(c.toString).toSeq.flatten
    } yield pre + r + suf
  }

  def sbdomain(): Seq[String] = {
    for {
      i <- 1 until domain.length - 1
      if domain(i) != '-' && domain(i - 1) != '.'
    } yield domain.take(i) + "." + domain.drop(i)
  }

  def transposition(): Set[String] = {
    (0 until domain.length - 1).map(i => domain.take(i) + domain(i + 1) + domain(i) + domain.drop(i + 2)).toSet
  }

  def vowelSwap(): Seq[String] = {
    val vowels = "aeiou"
    for {
      i <- 0 until domain.length
      vowel <- vowels
      if vowels.contains(domain(i))
    } yield domain.take(i) + vowel + domain.drop(i + 1)
  }

  def plural(): Seq[String] = {
    for {
      i <- 2 until domain.length - 2
    } yield domain.take(i + 1) + (if (Set('s', 'x', 'z').contains(domain(i))) "es" else "s") + domain.drop(i + 1)
  }

  def addition(): Set[String] = {
    val result = mutable.Set[String]()
    if (domain.contains('-')) {
      val parts = domain.split('-')
      for {
        i <- (48 to 57) ++ (97 to 122)
        p <- 1 until parts.length
      } {
        result.add((parts.take(p).mkString("-") + i.toChar + "-" + parts.drop(p).mkString("-")))
      }
    }
    for (i <- (48 to 57) ++ (97 to 122)) {
      result.add(domain + i.toChar)
    }
    result.toSet
  }

  def dictionary(): Set[String] = {
    val result = mutable.Set[String]()
    for (word <- dictionary) {
      if (!(domain.startsWith(word) && domain.endsWith(word))) {
        result.add(domain + "-" + word)
        result.add(domain + word)
        result.add(word + "-" + domain)
        result.add(word + domain)
      }
    }
    if (domain.contains('-')) {
      val parts = domain.split('-')
      for (word <- dictionary) {
        result.add(parts.dropRight(1).mkString("-") + "-" + word)
        result.add(word + "-" + parts.drop(1).mkString("-"))
      }
    }
    result.toSet
  }

  def tldMethod(): Set[String] = {
    if (tldDictionary.contains(tld)) {
      tldDictionary = tldDictionary.filterNot(_ == tld)
    }
    tldDictionary.toSet
  }

  def generate(fuzzers: Seq[String] = Seq()): Unit = {
    domains.clear()
    if (fuzzers.isEmpty || fuzzers.contains("*original")) {
      domains.add(Permutation(fuzzer = "*original", domain = Seq(subdomain, domain, tld).filter(_.nonEmpty).mkString(".")))
    }
    for (fName <- fuzzers.isEmpty match {
      case true => Seq("addition", "bitsquatting", "cyrillic", "homoglyph", "hyphenation", "insertion", "omission", "plural", "repetition", "replacement", "subdomain", "transposition", "vowel-swap", "dictionary")
      case false => fuzzers
    }) {
      try {
        val f = getClass.getDeclaredMethod("_" + fName.replace("-", "_")).invoke(this).asInstanceOf[Seq[String]]
        for (domain <- f) {
          domains.add(Permutation(fuzzer = fName, domain = Seq(subdomain, domain, tld).filter(_.nonEmpty).mkString(".")))
        }
      } catch {
        case _: NoSuchMethodException => // Ignore
      }
    }
    if (fuzzers.isEmpty || fuzzers.contains("tld-swap")) {
      for (tld <- tldMethod()) {
        domains.add(Permutation(fuzzer = "tld-swap", domain = Seq(subdomain, domain, tld).filter(_.nonEmpty).mkString(".")))
      }
    }
    if (fuzzers.isEmpty || fuzzers.contains("various")) {
      if (tld.contains('.')) {
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain, domain, tld.split('.').last).filter(_.nonEmpty).mkString(".")))
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain, domain + tld).filter(_.nonEmpty).mkString(".")))
      } else {
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain, domain + tld, tld).filter(_.nonEmpty).mkString(".")))
      }
      if (tld != "com" && !tld.contains('.')) {
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain, domain + "-" + tld, "com").filter(_.nonEmpty).mkString(".")))
      }
      if (subdomain.nonEmpty) {
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain + domain, tld).filter(_.nonEmpty).mkString(".")))
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain.replace(".", "") + domain, tld).filter(_.nonEmpty).mkString(".")))
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain + "-" + domain, tld).filter(_.nonEmpty).mkString(".")))
        domains.add(Permutation(fuzzer = "various", domain = Seq(subdomain.replace(".", "-") + "-" + domain, tld).filter(_.nonEmpty).mkString(".")))
      }
    }
//    def punycode(domain: Map[String, String]): Map[String, String] = {
//      try {
//        domain.updated("domain", idna.encode(domain("domain")).decode())
//      } catch {
//        case _: Exception => domain.updated("domain", "")
//      }
//    }
//    domains = domains.map(punycode).toSet
    // Implement VALID_FQDN_REGEX logic here
  }

  def permutations(registered: Boolean = false, unregistered: Boolean = false, dnsAll: Boolean = false, unicode: Boolean = false): Seq[Permutation] = {
    val dmns = (registered, unregistered) match {
      case (true, false) => domains.filter(_.isRegistered).toSeq
      case (false, true) => domains.filterNot(_.isRegistered).toSeq
      case _ => domains.toSeq
    }
//    if (!dnsAll) {
//      dmns.map { x =>
//        if (x.isRegistered) {
//          val dnsKeys = Seq("dns_ns", "dns_a", "dns_aaaa", "dns_mx")
//          dnsKeys.foreach(k => if (x.domain.contains(k)) x.domain.updated(k, x.domain(k).take(1)))
//        }
//        x
//      }
//    }
//    if (unicode) {
//      dmns.map { x =>
//        x.updated("domain", idna.decode(x("domain")))
//      }
//    }
    dmns.sorted
  }
}



