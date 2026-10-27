import { motion } from "framer-motion";

export default function SplitText({ text, className = "", delay = 0, stagger = 0.04, as: Tag = "span" }) {
  const words = text.split(" ");
  return (
    <Tag className={className} style={{ display: "inline-block" }}>
      {words.map((word, wi) => (
        <span key={wi} style={{ display: "inline-block", overflow: "hidden", verticalAlign: "bottom", marginRight: "0.25em", paddingBottom: "0.05em" }}>
          <motion.span
            style={{ display: "inline-block" }}
            initial={{ y: "110%", opacity: 0 }}
            animate={{ y: "0%", opacity: 1 }}
            transition={{ duration: 0.9, delay: delay + wi * stagger, ease: [0.16, 1, 0.3, 1] }}
          >
            {word}
          </motion.span>
        </span>
      ))}
    </Tag>
  );
}
