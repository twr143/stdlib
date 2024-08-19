package example

object Hello extends App{
  println(Hello().greeting)
}

case class Hello() {
  val ss: List[String] = List("1","2","3","4")
  val greeting: List[String] = ss match {
    case List(f , _ , third, forth , _*) => Some(f).toList
    case _ => None.toList
  }
  val list1 = List(Some(1),None,None,Some(2))
  val l2 = list1.flatten

  def anyFunction(list: List[Int]): Unit =
    list match {
      // ...methods that have already been shown
      case first :: second :: third :: Nil  => println(s"List has only 2 elements: $first and $second")
      case first :: second :: tail => println(s"First: $first \nSecond: $second \nTail: $tail")
    }
}
