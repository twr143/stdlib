import Dependencies._
Global / onChangedBuildSource := ReloadOnSourceChanges

ThisBuild / scalaVersion     := "2.12.18"
ThisBuild / version          := "0.1.0-SNAPSHOT"
ThisBuild / organization     := "org.iv"
ThisBuild / organizationName := "stdlib"

lazy val root = (project in file("."))
  .settings(
    name := "stdlib",
    libraryDependencies += munit % Test
  )

// See https://www.scala-sbt.org/1.x/docs/Using-Sonatype.html for instructions on how to publish to Sonatype.
